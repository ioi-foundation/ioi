use super::brief::{normalize_studio_outcome_planning_value, parse_studio_json_object_value};
use super::shared::{studio_planning_trace, truncate_planning_preview};
use crate::studio::judging::studio_artifact_refinement_context_view;
use crate::studio::*;
use crate::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    StudioArtifactClass, StudioArtifactDeliverableShape, StudioArtifactPersistenceMode,
    StudioExecutionStrategy, StudioExecutionSubstrate, StudioNormalizedRequestFrame,
    StudioOutcomeArtifactRequest, StudioOutcomeArtifactScope,
    StudioOutcomeArtifactVerificationRequest, StudioOutcomeKind, StudioOutcomePlanningPayload,
    StudioPresentationSurface, StudioRendererKind, StudioRuntimeProvenanceKind,
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
    planning =
        cohere_planning_with_intent_contract(intent, active_artifact_id, active_artifact, planning);
    planning.artifact = planning
        .artifact
        .map(|request| reconcile_outcome_artifact_request_with_intent(intent, request));
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

fn intent_terms(intent: &str) -> Vec<String> {
    StudioIntentContext::new(intent).terms().to_vec()
}

fn merge_routing_hints(target: &mut Vec<String>, incoming: Vec<String>) {
    for hint in incoming {
        if target.iter().any(|existing| existing == &hint) {
            continue;
        }
        target.push(hint);
    }
}

fn planning_hint_flag(planning: &StudioOutcomePlanningPayload, needle: &str) -> bool {
    planning
        .routing_hints
        .iter()
        .any(|hint| hint == needle || hint.starts_with(&format!("{needle}:")))
}

fn planning_tool_widget_family(planning: &StudioOutcomePlanningPayload) -> Option<&str> {
    planning
        .routing_hints
        .iter()
        .find_map(|hint| hint.strip_prefix("tool_widget:"))
}

fn planning_artifact_renderer(
    planning: &StudioOutcomePlanningPayload,
) -> Option<StudioRendererKind> {
    planning.artifact.as_ref().map(|artifact| artifact.renderer)
}

fn should_override_planning_with_contract(
    planning: &StudioOutcomePlanningPayload,
    candidate: &StudioOutcomePlanningPayload,
) -> bool {
    if candidate.outcome_kind != planning.outcome_kind {
        return true;
    }

    if candidate.needs_clarification != planning.needs_clarification {
        return true;
    }

    match candidate.outcome_kind {
        StudioOutcomeKind::ToolWidget => {
            planning_tool_widget_family(planning) != planning_tool_widget_family(candidate)
                || !planning_hint_flag(planning, "narrow_surface_preferred")
        }
        StudioOutcomeKind::Visualizer => {
            planning.outcome_kind != StudioOutcomeKind::Visualizer
                || !planning_hint_flag(planning, "inline_visual_requested")
        }
        StudioOutcomeKind::Artifact => {
            planning_artifact_renderer(planning) != planning_artifact_renderer(candidate)
        }
        StudioOutcomeKind::Conversation => candidate.routing_hints.iter().any(|hint| {
            !planning
                .routing_hints
                .iter()
                .any(|existing| existing == hint)
        }),
    }
}

fn cohere_planning_with_intent_contract(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
    planning: StudioOutcomePlanningPayload,
) -> StudioOutcomePlanningPayload {
    let contract_candidates = [
        deterministic_downloadable_artifact_route(intent, active_artifact_id, active_artifact),
        deterministic_workspace_artifact_route(intent, active_artifact_id, active_artifact),
        deterministic_document_clarification_route(intent, active_artifact_id, active_artifact),
        deterministic_single_document_artifact_route(intent, active_artifact_id, active_artifact),
        deterministic_generic_document_artifact_route(intent, active_artifact_id, active_artifact),
        deterministic_interactive_surface_artifact_route(
            intent,
            active_artifact_id,
            active_artifact,
        ),
    ];

    for candidate in contract_candidates.into_iter().flatten() {
        if should_override_planning_with_contract(&planning, &candidate) {
            studio_planning_trace(format!(
                "outcome_route:contract_override from={:?} to={:?} strategy={:?}",
                planning.outcome_kind, candidate.outcome_kind, candidate.execution_strategy
            ));
            return candidate;
        }
    }

    if let Some(candidate) = typed_non_artifact_candidate_from_topology(
        intent,
        active_artifact_id,
        active_artifact,
        &planning,
    ) {
        if should_override_planning_with_contract(&planning, &candidate) {
            studio_planning_trace(format!(
                "outcome_route:typed_override from={:?} to={:?} strategy={:?}",
                planning.outcome_kind, candidate.outcome_kind, candidate.execution_strategy
            ));
            return candidate;
        }
    }

    planning
}

fn specialized_clarification_question(frame: &StudioNormalizedRequestFrame) -> Option<String> {
    let blocking_slots = studio_request_frame_clarification_slots(frame);
    if blocking_slots.is_empty() {
        return None;
    }

    Some(match frame {
        StudioNormalizedRequestFrame::Weather(_) => {
            "Which city or area should Studio check for the weather?".to_string()
        }
        StudioNormalizedRequestFrame::Sports(_) => {
            if blocking_slots
                .iter()
                .any(|slot| slot == "team_or_target" || slot == "target")
            {
                "Which team, player, or matchup should Studio use for the sports lookup?"
                    .to_string()
            } else {
                "Which league should Studio use for the sports lookup?".to_string()
            }
        }
        StudioNormalizedRequestFrame::Places(_) => {
            if blocking_slots.iter().any(|slot| {
                matches!(
                    slot.as_str(),
                    "search_anchor" | "location_scope" | "location"
                )
            }) {
                "Which neighborhood, city, or anchor location should Studio search around?"
                    .to_string()
            } else {
                "What kind of place should Studio look for?".to_string()
            }
        }
        StudioNormalizedRequestFrame::Recipe(_) => {
            "Which dish or recipe should Studio make?".to_string()
        }
        StudioNormalizedRequestFrame::MessageCompose(_) => {
            if blocking_slots.iter().any(|slot| slot == "channel") {
                "Which channel should Studio draft this for: email, Slack, text, or chat?"
                    .to_string()
            } else if blocking_slots
                .iter()
                .any(|slot| slot == "recipient_context")
            {
                "Who is this message for, or how should Studio describe the recipient context?"
                    .to_string()
            } else {
                "Should Studio draft a new message, reply to someone, or summarize a thread?"
                    .to_string()
            }
        }
        StudioNormalizedRequestFrame::UserInput(_) => {
            "What options or decision shape should Studio present?".to_string()
        }
    })
}

fn typed_tool_widget_candidate(
    context: &StudioIntentContext,
    frame: &StudioNormalizedRequestFrame,
) -> Option<StudioOutcomePlanningPayload> {
    let (widget_family, confidence) = match frame {
        StudioNormalizedRequestFrame::Weather(_) => ("weather", 0.95),
        StudioNormalizedRequestFrame::Sports(_) => ("sports", 0.95),
        StudioNormalizedRequestFrame::Places(_) => ("places", 0.95),
        StudioNormalizedRequestFrame::Recipe(_) => ("recipe", 0.94),
        StudioNormalizedRequestFrame::UserInput(_) => ("user_input", 0.94),
        StudioNormalizedRequestFrame::MessageCompose(_) => return None,
    };

    let clarification_slots = studio_request_frame_clarification_slots(frame);
    let needs_clarification = !clarification_slots.is_empty();
    let mut routing_hints = vec![
        format!("tool_widget:{widget_family}"),
        "narrow_surface_preferred".to_string(),
        "no_persistent_artifact_requested".to_string(),
    ];

    match frame {
        StudioNormalizedRequestFrame::Weather(_) => {
            if context.weather_advice_request() {
                routing_hints.push("weather_advice_request".to_string());
            }
            if clarification_slots.iter().any(|slot| slot == "location") {
                routing_hints.push("location_required_for_weather_advice".to_string());
            }
        }
        StudioNormalizedRequestFrame::UserInput(user_input) => {
            routing_hints.push("user_input_preferred".to_string());
            if context.requests_prioritization() {
                routing_hints.push("prioritization_request".to_string());
            }
            if !user_input.explicit_options_present {
                routing_hints.push("structured_input_options_missing".to_string());
            }
        }
        _ => {}
    }

    if matches!(widget_family, "weather" | "sports" | "places") && context.currentness_pressure() {
        routing_hints.push("currentness_override".to_string());
    }

    Some(StudioOutcomePlanningPayload {
        outcome_kind: StudioOutcomeKind::ToolWidget,
        execution_strategy: StudioExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence,
        needs_clarification,
        clarification_questions: specialized_clarification_question(frame)
            .into_iter()
            .collect(),
        routing_hints,
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    })
}

fn typed_message_compose_candidate(
    frame: &StudioNormalizedRequestFrame,
) -> Option<StudioOutcomePlanningPayload> {
    let StudioNormalizedRequestFrame::MessageCompose(_) = frame else {
        return None;
    };
    let clarification_slots = studio_request_frame_clarification_slots(frame);
    let needs_clarification = !clarification_slots.is_empty();
    Some(StudioOutcomePlanningPayload {
        outcome_kind: StudioOutcomeKind::Conversation,
        execution_strategy: StudioExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: if needs_clarification { 0.91 } else { 0.96 },
        needs_clarification,
        clarification_questions: specialized_clarification_question(frame)
            .into_iter()
            .collect(),
        routing_hints: vec![
            "message_compose_surface".to_string(),
            "no_persistent_artifact_requested".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    })
}

fn typed_non_artifact_candidate_from_topology(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
    planning: &StudioOutcomePlanningPayload,
) -> Option<StudioOutcomePlanningPayload> {
    if active_artifact_id.is_some() || active_artifact.is_some() {
        return None;
    }

    let context = StudioIntentContext::new(intent);
    if planning.outcome_kind == StudioOutcomeKind::Artifact
        && (explicit_single_document_renderer_from_intent(intent).is_some()
            || explicit_downloadable_export_format_from_intent(intent).is_some()
            || explicit_workspace_artifact_recipe_from_intent(intent).is_some()
            || intent_requests_downloadable_fileset(intent)
            || intent_supports_bundle_manifest_renderer(intent)
            || implicit_generic_document_artifact_reason(intent).is_some()
            || implicit_interactive_surface_artifact_reason(intent).is_some())
    {
        return None;
    }
    let projection = derive_studio_topology_projection(
        intent,
        active_artifact_id,
        None,
        planning.outcome_kind,
        planning.execution_strategy,
        planning.execution_mode_decision.as_ref(),
        planning.confidence,
        planning.needs_clarification,
        &planning.clarification_questions,
        &planning.routing_hints,
        planning.artifact.as_ref(),
    );

    if let Some(frame) = projection.request_frame.as_ref() {
        if let Some(candidate) = typed_tool_widget_candidate(&context, frame) {
            return Some(candidate);
        }
        if let Some(candidate) = typed_message_compose_candidate(frame) {
            return Some(candidate);
        }
    }

    if let Some(reason) = explicit_visualizer_signal_from_intent(intent) {
        return Some(StudioOutcomePlanningPayload {
            outcome_kind: StudioOutcomeKind::Visualizer,
            execution_strategy: StudioExecutionStrategy::SinglePass,
            execution_mode_decision: None,
            confidence: 0.95,
            needs_clarification: false,
            clarification_questions: Vec::new(),
            routing_hints: vec![
                reason.to_string(),
                "no_persistent_artifact_requested".to_string(),
            ],
            lane_frame: None,
            request_frame: None,
            source_selection: None,
            retained_lane_state: None,
            lane_transitions: Vec::new(),
            orchestration_state: None,
            artifact: None,
        });
    }

    if context.currentness_scope_ambiguous() {
        return Some(StudioOutcomePlanningPayload {
            outcome_kind: StudioOutcomeKind::Conversation,
            execution_strategy: StudioExecutionStrategy::PlanExecute,
            execution_mode_decision: None,
            confidence: 0.86,
            needs_clarification: true,
            clarification_questions: vec![
                "Do you mean local events, a specific topic, or general news this week?"
                    .to_string(),
            ],
            routing_hints: vec![
                "currentness_override".to_string(),
                "currentness_scope_ambiguous".to_string(),
                "clarification_required_for_currentness".to_string(),
                "shared_answer_surface".to_string(),
                "no_persistent_artifact_requested".to_string(),
            ],
            lane_frame: None,
            request_frame: None,
            source_selection: None,
            retained_lane_state: None,
            lane_transitions: Vec::new(),
            orchestration_state: None,
            artifact: None,
        });
    }

    if currentness_pressure_from_intent(intent) && !intent_requests_created_deliverable(intent) {
        return Some(StudioOutcomePlanningPayload {
            outcome_kind: StudioOutcomeKind::Conversation,
            execution_strategy: StudioExecutionStrategy::AdaptiveWorkGraph,
            execution_mode_decision: None,
            confidence: 0.91,
            needs_clarification: false,
            clarification_questions: Vec::new(),
            routing_hints: vec![
                "currentness_override".to_string(),
                "no_persistent_artifact_requested".to_string(),
                "shared_answer_surface".to_string(),
            ],
            lane_frame: None,
            request_frame: None,
            source_selection: None,
            retained_lane_state: None,
            lane_transitions: Vec::new(),
            orchestration_state: None,
            artifact: None,
        });
    }

    if workspace_grounding_required_from_intent(intent) {
        return Some(StudioOutcomePlanningPayload {
            outcome_kind: StudioOutcomeKind::Conversation,
            execution_strategy: StudioExecutionStrategy::PlanExecute,
            execution_mode_decision: None,
            confidence: 0.93,
            needs_clarification: false,
            clarification_questions: Vec::new(),
            routing_hints: vec![
                "workspace_grounding_required".to_string(),
                "coding_workspace_context".to_string(),
                "no_persistent_artifact_requested".to_string(),
            ],
            lane_frame: None,
            request_frame: None,
            source_selection: None,
            retained_lane_state: None,
            lane_transitions: Vec::new(),
            orchestration_state: None,
            artifact: None,
        });
    }

    None
}

fn normalized_intent_text(intent: &str) -> String {
    StudioIntentContext::new(intent).normalized().to_string()
}

fn terms_contain_any(terms: &[String], candidates: &[&str]) -> bool {
    terms
        .iter()
        .any(|term| candidates.iter().any(|candidate| term == candidate))
}

fn normalized_contains_any(normalized: &str, phrases: &[&str]) -> bool {
    phrases.iter().any(|phrase| normalized.contains(phrase))
}

fn intent_requests_downloadable_fileset(intent: &str) -> bool {
    StudioIntentContext::new(intent).requests_downloadable_fileset()
}

fn intent_supports_bundle_manifest_renderer(intent: &str) -> bool {
    StudioIntentContext::new(intent).supports_bundle_manifest_renderer()
}

fn intent_requests_created_deliverable(intent: &str) -> bool {
    StudioIntentContext::new(intent).requests_created_deliverable()
}

fn intent_explicit_generic_artifact_signal(intent: &str) -> bool {
    StudioIntentContext::new(intent).explicit_generic_artifact_signal()
}

fn explicit_downloadable_export_format_from_intent(intent: &str) -> Option<&'static str> {
    StudioIntentContext::new(intent).explicit_downloadable_export_format()
}

fn intent_prefers_message_compose_surface(intent: &str) -> bool {
    StudioIntentContext::new(intent).prefers_message_compose_surface()
}

fn currentness_pressure_from_intent(intent: &str) -> bool {
    StudioIntentContext::new(intent).currentness_pressure()
}

fn workspace_grounding_required_from_intent(intent: &str) -> bool {
    StudioIntentContext::new(intent).workspace_grounding_required()
}

fn explicit_visualizer_signal_from_intent(intent: &str) -> Option<&'static str> {
    StudioIntentContext::new(intent)
        .explicit_visualizer_signal()
        .or_else(|| {
            let normalized = normalized_intent_text(intent);
            normalized_contains_any(
                &normalized,
                &[
                    "inline visual",
                    "inline visualizer",
                    "render inline",
                    "visualize this inline",
                    "show a quick diagram",
                    "show an inline diagram",
                    "show a quick chart",
                ],
            )
            .then_some("inline_visual_requested")
        })
}

fn explicit_single_document_renderer_from_intent(
    intent: &str,
) -> Option<(StudioRendererKind, &'static str)> {
    let normalized = normalized_intent_text(intent);

    if normalized.contains("interactive html artifact")
        || normalized.contains("interactive html")
        || normalized.contains("html canvas artifact")
        || normalized.contains("html canvas")
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
        || normalized.contains("markdown brief")
        || normalized.contains("markdown report")
        || normalized.contains("markdown checklist")
        || normalized.contains("brief in markdown")
        || normalized.contains("report in markdown")
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

fn explicit_workspace_artifact_recipe_from_intent(
    intent: &str,
) -> Option<(&'static str, &'static str)> {
    let normalized = normalized_intent_text(intent);
    let terms = intent_terms(intent);
    let explicit_workspace_phrase = normalized_contains_any(
        &normalized,
        &[
            "workspace project",
            "workspace app",
            "workspace artifact",
            "workspace surface",
            "workspace repo",
            "workspace repository",
            "multi-file workspace",
        ],
    );
    let multi_file_signal = normalized_contains_any(
        &normalized,
        &[
            "separate components",
            "multiple components",
            "separate files",
            "multiple files",
            "multi-file",
            "file tree",
            "project structure",
        ],
    );
    let react_signal = terms_contain_any(&terms, &["react", "jsx", "tsx"]);
    let vite_signal = normalized_contains_any(
        &normalized,
        &[
            "react + vite",
            "react+vite",
            "react vite",
            "vite + react",
            "vite react",
            "vite project",
            "vite app",
        ],
    ) || terms_contain_any(&terms, &["vite"]);
    let stateful_app_signal = normalized_contains_any(
        &normalized,
        &["local state", "shared state", "routing", "filters"],
    ) || terms_contain_any(
        &terms,
        &[
            "components",
            "component",
            "state",
            "filters",
            "tracker",
            "dashboard",
        ],
    );
    let requires_workspace = explicit_workspace_phrase
        || (vite_signal && (multi_file_signal || react_signal || stateful_app_signal));
    if !requires_workspace {
        return None;
    }

    let recipe = if react_signal
        || normalized_contains_any(
            &normalized,
            &[
                "react + vite",
                "react+vite",
                "react vite",
                "vite + react",
                "vite react",
            ],
        ) {
        "react-vite"
    } else {
        "vite-static-html"
    };
    let reason = if explicit_workspace_phrase {
        "explicit_workspace_project_deliverable"
    } else {
        "multi_file_workspace_required"
    };
    Some((recipe, reason))
}

fn deterministic_downloadable_artifact_route(
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

    let export_format = explicit_downloadable_export_format_from_intent(intent)?;
    let request = canonicalize_artifact_request(StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::DownloadableFile,
        deliverable_shape: StudioArtifactDeliverableShape::FileSet,
        renderer: StudioRendererKind::DownloadCard,
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
            require_render: false,
            require_build: false,
            require_preview: false,
            require_export: true,
            require_diff_review: false,
        },
    });
    let execution_strategy =
        studio_execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(&request));

    Some(StudioOutcomePlanningPayload {
        outcome_kind: StudioOutcomeKind::Artifact,
        execution_strategy,
        execution_mode_decision: None,
        confidence: 0.98,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "persistent_artifact_requested".to_string(),
            "downloadable_export_requested".to_string(),
            format!("download_format:{export_format}"),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(request),
    })
}

fn deterministic_workspace_artifact_route(
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

    let (workspace_recipe_id, reason) = explicit_workspace_artifact_recipe_from_intent(intent)?;
    let request = canonicalize_artifact_request(StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::WorkspaceProject,
        deliverable_shape: StudioArtifactDeliverableShape::WorkspaceProject,
        renderer: StudioRendererKind::WorkspaceSurface,
        presentation_surface: StudioPresentationSurface::TabbedPanel,
        persistence: StudioArtifactPersistenceMode::WorkspaceFilesystem,
        execution_substrate: StudioExecutionSubstrate::WorkspaceRuntime,
        workspace_recipe_id: Some(workspace_recipe_id.to_string()),
        presentation_variant_id: None,
        scope: StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: true,
            mutation_boundary: vec!["workspace".to_string()],
        },
        verification: StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: true,
            require_preview: true,
            require_export: false,
            require_diff_review: true,
        },
    });
    let execution_strategy =
        studio_execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(&request));
    studio_planning_trace(format!(
        "outcome_route:deterministic renderer={:?} strategy={execution_strategy:?} reason={reason} workspace_recipe_id={workspace_recipe_id}",
        request.renderer
    ));
    Some(StudioOutcomePlanningPayload {
        outcome_kind: StudioOutcomeKind::Artifact,
        execution_strategy,
        execution_mode_decision: None,
        confidence: 0.98,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "persistent_artifact_requested".to_string(),
            reason.to_string(),
            "workspace_runtime_required".to_string(),
            format!("workspace_recipe:{workspace_recipe_id}"),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(request),
    })
}

fn intent_is_under_specified_document_request(intent: &str) -> bool {
    let normalized = normalized_intent_text(intent);
    if normalized.is_empty() || explicit_single_document_renderer_from_intent(intent).is_some() {
        return false;
    }
    if !(normalized.contains("report")
        || normalized.contains("brief")
        || normalized.contains("document")
        || normalized.contains("checklist"))
    {
        return false;
    }

    let subject_markers = [
        " about ",
        " on ",
        " of ",
        " explaining ",
        " that explains ",
        " that explain ",
        " covering ",
        " regarding ",
        " summarizing ",
        " summary of ",
    ];
    if subject_markers
        .iter()
        .any(|marker| normalized.contains(marker))
    {
        return false;
    }

    let remaining_tokens = normalized
        .split(|character: char| !character.is_alphanumeric())
        .filter(|token| !token.is_empty())
        .map(|token| token.to_ascii_lowercase())
        .filter(|token| {
            !matches!(
                token.as_str(),
                "a" | "an"
                    | "brief"
                    | "build"
                    | "checklist"
                    | "create"
                    | "document"
                    | "draft"
                    | "generate"
                    | "give"
                    | "make"
                    | "me"
                    | "prepare"
                    | "produce"
                    | "report"
                    | "the"
                    | "write"
            )
        })
        .collect::<Vec<_>>();

    remaining_tokens.is_empty()
}

fn deterministic_document_clarification_route(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> Option<StudioOutcomePlanningPayload> {
    if active_artifact_id.is_some() || active_artifact.is_some() {
        return None;
    }
    if !intent_requests_created_deliverable(intent)
        || !intent_is_under_specified_document_request(intent)
    {
        return None;
    }

    Some(StudioOutcomePlanningPayload {
        outcome_kind: StudioOutcomeKind::Conversation,
        execution_strategy: StudioExecutionStrategy::PlanExecute,
        execution_mode_decision: None,
        confidence: 0.94,
        needs_clarification: true,
        clarification_questions: vec!["What should the report cover?".to_string()],
        routing_hints: vec![
            "artifact_clarification_required".to_string(),
            "under_specified_document_request".to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: None,
    })
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
        routing_hints: vec![
            "persistent_artifact_requested".to_string(),
            reason.to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(request),
    })
}

fn implicit_generic_document_artifact_reason(intent: &str) -> Option<&'static str> {
    if !intent_requests_created_deliverable(intent) {
        return None;
    }

    if intent_prefers_message_compose_surface(intent) {
        return None;
    }

    if explicit_single_document_renderer_from_intent(intent).is_some()
        || explicit_downloadable_export_format_from_intent(intent).is_some()
        || explicit_workspace_artifact_recipe_from_intent(intent).is_some()
        || intent_requests_downloadable_fileset(intent)
        || intent_supports_bundle_manifest_renderer(intent)
        || explicit_visualizer_signal_from_intent(intent).is_some()
    {
        return None;
    }

    intent_explicit_generic_artifact_signal(intent)
        .then_some("generic_document_artifact_defaults_to_markdown")
}

fn deterministic_generic_document_artifact_route(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> Option<StudioOutcomePlanningPayload> {
    if active_artifact_id.is_some() || active_artifact.is_some() {
        return None;
    }

    let reason = implicit_generic_document_artifact_reason(intent)?;
    let request = canonicalize_artifact_request(StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::Document,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::Markdown,
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
            require_export: false,
            require_diff_review: false,
        },
    });
    let execution_strategy =
        studio_execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(&request));
    studio_planning_trace(format!(
        "outcome_route:deterministic renderer={:?} strategy={execution_strategy:?} reason={reason}",
        request.renderer
    ));

    Some(StudioOutcomePlanningPayload {
        outcome_kind: StudioOutcomeKind::Artifact,
        execution_strategy,
        execution_mode_decision: None,
        confidence: 0.97,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "persistent_artifact_requested".to_string(),
            reason.to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(request),
    })
}

fn implicit_interactive_surface_artifact_reason(intent: &str) -> Option<&'static str> {
    let normalized = normalized_intent_text(intent);
    let terms = intent_terms(intent);
    let interactive_surface_noun = terms_contain_any(
        &terms,
        &[
            "calculator",
            "estimator",
            "simulator",
            "configurator",
            "planner",
            "dashboard",
            "tracker",
            "quiz",
        ],
    );
    let adjustable_surface_signal = normalized_contains_any(
        &normalized,
        &[
            "where i can",
            "where we can",
            "adjust ",
            "change ",
            "set ",
            "slider",
            "sliders",
            "toggle",
            "toggles",
            "controls",
            "control panel",
        ],
    );
    let artifact_like_surface_shape = normalized.starts_with("a ")
        || normalized.starts_with("an ")
        || normalized.starts_with("the ")
        || normalized.contains("interactive ");

    (interactive_surface_noun && (adjustable_surface_signal || artifact_like_surface_shape))
        .then_some("implicit_interactive_surface_deliverable")
}

fn deterministic_interactive_surface_artifact_route(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&StudioArtifactRefinementContext>,
) -> Option<StudioOutcomePlanningPayload> {
    if active_artifact_id.is_some() || active_artifact.is_some() {
        return None;
    }

    let reason = implicit_interactive_surface_artifact_reason(intent)?;
    let request = canonicalize_artifact_request(StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::SharedArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
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
            require_export: false,
            require_diff_review: false,
        },
    });
    let execution_strategy =
        studio_execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(&request));
    studio_planning_trace(format!(
        "outcome_route:deterministic renderer={:?} strategy={execution_strategy:?} reason={reason}",
        request.renderer
    ));
    Some(StudioOutcomePlanningPayload {
        outcome_kind: StudioOutcomeKind::Artifact,
        execution_strategy,
        execution_mode_decision: None,
        confidence: 0.95,
        needs_clarification: false,
        clarification_questions: Vec::new(),
        routing_hints: vec![
            "persistent_artifact_requested".to_string(),
            reason.to_string(),
        ],
        lane_frame: None,
        request_frame: None,
        source_selection: None,
        retained_lane_state: None,
        lane_transitions: Vec::new(),
        orchestration_state: None,
        artifact: Some(request),
    })
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

    if request.renderer == StudioRendererKind::BundleManifest
        && !matches!(request.artifact_class, StudioArtifactClass::CodePatch)
        && !intent_supports_bundle_manifest_renderer(intent)
    {
        let original_renderer = request.renderer;
        request.renderer = StudioRendererKind::Markdown;
        request.artifact_class = StudioArtifactClass::Document;
        request.deliverable_shape = StudioArtifactDeliverableShape::SingleFile;
        request.presentation_surface = StudioPresentationSurface::SidePanel;
        request.persistence = StudioArtifactPersistenceMode::SharedArtifactScoped;
        request.execution_substrate = StudioExecutionSubstrate::None;
        request.workspace_recipe_id = None;
        request.presentation_variant_id = None;
        request.scope.create_new_workspace = false;
        request.verification.require_build = false;
        request.verification.require_preview = false;
        request.verification.require_diff_review = false;
        request.verification.require_export = false;
        let request = canonicalize_artifact_request(request);
        studio_planning_trace(format!(
            "outcome_route:renderer_reconciled from={original_renderer:?} to={:?} reason=single_document_default_for_non_bundle_intent",
            request.renderer
        ));
        return request;
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
