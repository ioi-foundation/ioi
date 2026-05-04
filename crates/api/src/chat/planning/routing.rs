use super::brief::{normalize_chat_outcome_planning_value, parse_chat_json_object_value};
use super::shared::{chat_planning_trace, truncate_planning_preview};
use crate::chat::intent_signals::ChatIntentContext;
use crate::chat::specialized_policy::chat_normalized_request_clarification_slots;
use crate::chat::validation::chat_artifact_refinement_context_view;
use crate::chat::*;
use crate::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::ChatSourceFamily;
use ioi_types::app::{
    ChatArtifactClass, ChatArtifactDeliverableShape, ChatArtifactPersistenceMode,
    ChatExecutionStrategy, ChatExecutionSubstrate, ChatNormalizedRequest,
    ChatOutcomeArtifactRequest, ChatOutcomeArtifactScope, ChatOutcomeArtifactVerificationRequest,
    ChatOutcomeKind, ChatOutcomePlanningPayload, ChatPresentationSurface, ChatRendererKind,
    ChatRuntimeProvenanceKind,
};
use serde_json::json;
use std::sync::Arc;

fn compact_local_outcome_router_refinement_context(
    refinement: Option<&ChatArtifactRefinementContext>,
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
        "interactionPlanCount": refinement
            .blueprint
            .as_ref()
            .map(|blueprint| blueprint.interaction_plan.len())
            .unwrap_or_default(),
        "interactionGraphCount": refinement
            .artifact_ir
            .as_ref()
            .map(|artifact_ir| artifact_ir.interaction_graph.len())
            .unwrap_or_default(),
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
    active_artifact: Option<&ChatArtifactRefinementContext>,
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
           \"executionStrategy\": \"single_pass\" | \"direct_author\" | \"plan_execute\" | \"micro_work_graph\" | \"adaptive_work_graph\",\n\
           \"confidence\": <0_to_1_float>,\n\
           \"needsClarification\": <boolean>,\n\
           \"clarificationQuestions\": [<string>],\n\
           \"decisionEvidence\": [<string>],\n\
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
         - html_iframe may be artifactClass=document for plain authored HTML documents, or interactive_single_file only when the request truly needs browser interaction.\n\
         - workspace_surface only when a real multi-file workspace and supervised preview runtime are required.\n\
         - Explicit medium-plus-deliverable requests are sufficiently specified artifact work.\n\
         - direct_author only for a fresh coherent single-file artifact; follow-up edits should continue the active artifact.\n\
         - For tool_widget, include exactly one decisionEvidence entry of tool_widget:weather | tool_widget:recipe | tool_widget:sports | tool_widget:places | tool_widget:user_input.\n\
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
            "content": "You are Chat's typed outcome router for local runtimes. Return exactly one JSON object, rely on renderer-derived defaults when fields are omitted, continue the active artifact for follow-up edits, and never use lexical fallbacks."
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
    active_artifact: &ChatArtifactRefinementContext,
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
           \"executionStrategy\": \"single_pass\" | \"direct_author\" | \"plan_execute\" | \"micro_work_graph\" | \"adaptive_work_graph\",\n\
           \"confidence\": <0_to_1_float>,\n\
           \"needsClarification\": <boolean>,\n\
           \"clarificationQuestions\": [<string>],\n\
           \"decisionEvidence\": [<string>],\n\
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
            "content": "You are Chat's typed outcome router for local follow-up edits. Return exactly one JSON object, continue the active artifact by default, and rely on renderer-derived defaults when fields are omitted."
        },
        {
            "role": "user",
            "content": user_content
        }
    ])
}

fn build_chat_outcome_router_json_repair_prompt(
    intent: &str,
    raw_output: &str,
) -> serde_json::Value {
    let raw_preview = truncate_planning_preview(raw_output, 1200);
    json!([
        {
            "role": "system",
            "content": "You repair Chat typed outcome-router output. Return exactly one JSON object and no prose. Do not infer from keyword maps; preserve the safest typed route supported by the request and schema."
        },
        {
            "role": "user",
            "content": format!(
                "Original request:\n{intent}\n\nRouter output that failed JSON parsing:\n{raw_preview}\n\nReturn exactly one JSON object with camelCase fields:\n{{\"outcomeKind\":\"conversation\"|\"tool_widget\"|\"visualizer\"|\"artifact\",\"executionStrategy\":\"single_pass\"|\"direct_author\"|\"plan_execute\"|\"micro_work_graph\"|\"adaptive_work_graph\",\"confidence\":0.0,\"needsClarification\":false,\"clarificationQuestions\":[],\"decisionEvidence\":[\"json_parse_repair\"],\"artifact\":null}}\nUse artifact only when the request clearly asks for a persistent work product. Otherwise use conversation. JSON only."
            )
        }
    ])
}

pub fn chat_execution_strategy_for_outcome(
    outcome_kind: ChatOutcomeKind,
    artifact: Option<&ChatOutcomeArtifactRequest>,
) -> ChatExecutionStrategy {
    crate::execution::execution_strategy_for_outcome(outcome_kind, artifact)
}

pub async fn plan_chat_outcome_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&ChatArtifactRefinementContext>,
) -> Result<ChatOutcomePlanningPayload, String> {
    let runtime_provenance = runtime.chat_runtime_provenance();
    let compact_local_contract =
        runtime_provenance.kind == ChatRuntimeProvenanceKind::RealLocalRuntime;
    let router_max_tokens = if compact_local_contract { 224 } else { 768 };
    let payload = build_chat_outcome_router_prompt_for_runtime(
        intent,
        active_artifact_id,
        active_artifact,
        runtime_provenance.kind,
    );
    let input = serde_json::to_vec(&payload)
        .map_err(|error| format!("Failed to encode Chat outcome planning payload: {}", error))?;
    chat_planning_trace(format!(
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
        .map_err(|error| format!("Chat outcome planning inference failed: {}", error))?;
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Chat outcome planning utf8 decode failed: {}", error))?;
    chat_planning_trace(format!(
        "outcome_route:raw bytes={} preview={}",
        raw.len(),
        truncate_planning_preview(&raw, 240)
    ));
    let mut planning = match parse_chat_outcome_planning_payload(&raw) {
        Ok(planning) => planning,
        Err(parse_error) if compact_local_contract => {
            chat_planning_trace(format!(
                "outcome_route:parse_repair_start error={} raw_preview={}",
                parse_error,
                truncate_planning_preview(&raw, 240)
            ));
            let repair_payload = build_chat_outcome_router_json_repair_prompt(intent, &raw);
            let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                format!(
                    "Failed to encode Chat outcome planning repair payload: {}",
                    error
                )
            })?;
            let repair_output = runtime
                .execute_inference(
                    [0u8; 32],
                    &repair_input,
                    InferenceOptions {
                        temperature: 0.0,
                        json_mode: true,
                        max_tokens: 512,
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| {
                    format!(
                        "Chat outcome planning repair inference failed after parse error '{}': {}",
                        parse_error, error
                    )
                })?;
            let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                format!(
                    "Chat outcome planning repair utf8 decode failed after parse error '{}': {}",
                    parse_error, error
                )
            })?;
            chat_planning_trace(format!(
                "outcome_route:parse_repair_raw bytes={} preview={}",
                repair_raw.len(),
                truncate_planning_preview(&repair_raw, 240)
            ));
            parse_chat_outcome_planning_payload(&repair_raw).map_err(|repair_error| {
                format!(
                    "{}; JSON repair retry failed: {}",
                    parse_error, repair_error
                )
            })?
        }
        Err(parse_error) => return Err(parse_error),
    };
    planning.artifact = planning.artifact.map(canonicalize_artifact_request);
    enforce_contextual_routing_contract(&mut planning, intent, active_artifact_id, active_artifact);
    let contract_hints = default_decision_evidence_for_planning(&planning);
    merge_decision_evidence(&mut planning.decision_evidence, contract_hints);
    let planning_confidence = planning.confidence;
    apply_topology_projection_to_planning(
        &mut planning,
        intent,
        active_artifact_id,
        planning_confidence,
    );
    if clear_overeager_conversation_clarification(&mut planning) {
        apply_topology_projection_fields(
            &mut planning,
            intent,
            active_artifact_id,
            planning_confidence,
        );
    }
    chat_planning_trace(format!(
        "outcome_route:parsed outcome={:?} strategy={:?} confidence={} needs_clarification={} artifact_present={}",
        planning.outcome_kind,
        planning.execution_strategy,
        planning.confidence,
        planning.needs_clarification,
        planning.artifact.is_some()
    ));
    Ok(planning)
}

fn enforce_contextual_routing_contract(
    planning: &mut ChatOutcomePlanningPayload,
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&ChatArtifactRefinementContext>,
) {
    let context = ChatIntentContext::new(intent);
    let explicit_renderer = context
        .explicit_single_document_renderer()
        .map(|(renderer, _)| renderer);
    let explicit_artifact_request = (context.explicit_generic_artifact_signal()
        || explicit_renderer.is_some())
        && !context.explicitly_declines_persistent_artifact();
    let active_artifact_follow_up = active_artifact_id.is_some();
    let typed_workspace_artifact = planning.outcome_kind == ChatOutcomeKind::Artifact
        && planning.artifact.as_ref().is_some_and(|artifact| {
            matches!(
                artifact.renderer,
                ChatRendererKind::WorkspaceSurface | ChatRendererKind::BundleManifest
            ) || matches!(
                artifact.artifact_class,
                ChatArtifactClass::WorkspaceProject
                    | ChatArtifactClass::CodePatch
                    | ChatArtifactClass::ReportBundle
            ) || matches!(
                artifact.execution_substrate,
                ChatExecutionSubstrate::WorkspaceRuntime
            )
        });
    let artifact_allowed = explicit_artifact_request
        || active_artifact_follow_up
        || typed_workspace_artifact
        || context.requests_downloadable_fileset()
        || context.supports_bundle_manifest_renderer();

    if context.explicitly_declines_persistent_artifact() {
        force_conversation_route(planning);
        remove_decision_evidence(
            &mut planning.decision_evidence,
            &[
                "persistent_artifact_requested",
                "workspace_grounding_required",
                "coding_workspace_context",
            ],
        );
        merge_decision_evidence(
            &mut planning.decision_evidence,
            vec![
                "no_persistent_artifact_requested".to_string(),
                "shared_answer_surface".to_string(),
            ],
        );
    } else if context.runtime_lifecycle_grounding_required() {
        force_conversation_route(planning);
        merge_decision_evidence(
            &mut planning.decision_evidence,
            vec![
                "no_persistent_artifact_requested".to_string(),
                "shared_answer_surface".to_string(),
            ],
        );
    } else if explicit_artifact_request && planning.outcome_kind != ChatOutcomeKind::Artifact {
        let renderer = explicit_renderer.unwrap_or(ChatRendererKind::Markdown);
        force_artifact_route(planning, renderer);
    } else if planning.outcome_kind == ChatOutcomeKind::Artifact && !artifact_allowed {
        force_conversation_route(planning);
        merge_decision_evidence(
            &mut planning.decision_evidence,
            vec![
                "no_persistent_artifact_requested".to_string(),
                "shared_answer_surface".to_string(),
            ],
        );
    }

    if planning.outcome_kind == ChatOutcomeKind::Conversation {
        if let Some(widget_family) = context.tool_widget_family() {
            force_tool_widget_route(planning, widget_family);
        }
    } else if planning.outcome_kind == ChatOutcomeKind::ToolWidget {
        if let Some(widget_family) =
            tool_widget_family_hint(&planning.decision_evidence).map(str::to_string)
        {
            if matches!(
                widget_family.as_str(),
                "weather" | "sports" | "places" | "recipe"
            ) && context.tool_widget_family() != Some(widget_family.as_str())
            {
                force_conversation_route(planning);
                remove_decision_evidence(
                    &mut planning.decision_evidence,
                    &["tool_widget:", "narrow_surface_preferred"],
                );
                merge_decision_evidence(
                    &mut planning.decision_evidence,
                    vec![
                        "no_persistent_artifact_requested".to_string(),
                        "shared_answer_surface".to_string(),
                    ],
                );
            }
        }
    }

    if context.workspace_grounding_required() {
        merge_decision_evidence(
            &mut planning.decision_evidence,
            vec![
                "workspace_grounding_required".to_string(),
                "coding_workspace_context".to_string(),
            ],
        );
    } else if !matches!(
        planning.artifact.as_ref().map(|artifact| artifact.renderer),
        Some(ChatRendererKind::WorkspaceSurface)
    ) {
        remove_decision_evidence(
            &mut planning.decision_evidence,
            &["workspace_grounding_required", "coding_workspace_context"],
        );
    }

    preserve_active_artifact_contract(planning, &context, active_artifact);

    if planning.outcome_kind == ChatOutcomeKind::Artifact
        && context.explicit_interactive_single_document_signal()
    {
        let artifact = planning.artifact.get_or_insert_with(|| {
            default_artifact_request_for_renderer(ChatRendererKind::HtmlIframe)
        });
        if artifact.renderer == ChatRendererKind::HtmlIframe {
            artifact.artifact_class = ChatArtifactClass::InteractiveSingleFile;
            artifact.execution_substrate = ChatExecutionSubstrate::ClientSandbox;
            artifact.verification.require_render = true;
            merge_decision_evidence(
                &mut planning.decision_evidence,
                vec!["interactive_single_file_artifact".to_string()],
            );
        }
    }
}

fn active_refinement_has_interaction_contract(refinement: &ChatArtifactRefinementContext) -> bool {
    refinement.renderer == ChatRendererKind::HtmlIframe
        && (refinement
            .blueprint
            .as_ref()
            .is_some_and(|blueprint| !blueprint.interaction_plan.is_empty())
            || refinement
                .artifact_ir
                .as_ref()
                .is_some_and(|artifact_ir| !artifact_ir.interaction_graph.is_empty()))
}

fn preserve_active_artifact_contract(
    planning: &mut ChatOutcomePlanningPayload,
    context: &ChatIntentContext,
    active_artifact: Option<&ChatArtifactRefinementContext>,
) {
    if planning.outcome_kind != ChatOutcomeKind::Artifact {
        return;
    }
    let Some(active_artifact) = active_artifact else {
        return;
    };

    let explicit_renderer = context
        .explicit_single_document_renderer()
        .map(|(renderer, _)| renderer);
    let preserve_renderer = explicit_renderer.is_none();
    let mut artifact = planning
        .artifact
        .take()
        .unwrap_or_else(|| default_artifact_request_for_renderer(active_artifact.renderer));
    if preserve_renderer {
        artifact.renderer = active_artifact.renderer;
    }
    let mut artifact = canonicalize_artifact_request(artifact);

    if artifact.renderer == ChatRendererKind::HtmlIframe
        && active_refinement_has_interaction_contract(active_artifact)
    {
        artifact.artifact_class = ChatArtifactClass::InteractiveSingleFile;
        artifact.execution_substrate = ChatExecutionSubstrate::ClientSandbox;
        artifact.verification.require_render = true;
        merge_decision_evidence(
            &mut planning.decision_evidence,
            vec!["interactive_single_file_artifact".to_string()],
        );
    }

    planning.artifact = Some(artifact);
}

fn force_tool_widget_route(planning: &mut ChatOutcomePlanningPayload, widget_family: &str) {
    planning.outcome_kind = ChatOutcomeKind::ToolWidget;
    if planning.execution_strategy == ChatExecutionStrategy::SinglePass {
        planning.execution_strategy = ChatExecutionStrategy::PlanExecute;
    }
    planning.artifact = None;
    remove_decision_evidence(
        &mut planning.decision_evidence,
        &["no_persistent_artifact_requested", "shared_answer_surface"],
    );
    merge_decision_evidence(
        &mut planning.decision_evidence,
        vec![
            format!("tool_widget:{widget_family}"),
            "narrow_surface_preferred".to_string(),
        ],
    );
}

fn tool_widget_family_hint(decision_evidence: &[String]) -> Option<&str> {
    decision_evidence
        .iter()
        .find_map(|hint| hint.strip_prefix("tool_widget:"))
}

fn force_conversation_route(planning: &mut ChatOutcomePlanningPayload) {
    planning.outcome_kind = ChatOutcomeKind::Conversation;
    if matches!(
        planning.execution_strategy,
        ChatExecutionStrategy::DirectAuthor | ChatExecutionStrategy::AdaptiveWorkGraph
    ) {
        planning.execution_strategy = ChatExecutionStrategy::SinglePass;
    }
    planning.artifact = None;
    planning.needs_clarification = false;
    planning.clarification_questions.clear();
    remove_decision_evidence(
        &mut planning.decision_evidence,
        &[
            "persistent_artifact_requested",
            "downloadable_export_requested",
            "download_format:",
        ],
    );
}

fn force_artifact_route(planning: &mut ChatOutcomePlanningPayload, renderer: ChatRendererKind) {
    planning.outcome_kind = ChatOutcomeKind::Artifact;
    planning.execution_strategy = ChatExecutionStrategy::DirectAuthor;
    planning.needs_clarification = false;
    planning.clarification_questions.clear();
    planning.artifact = Some(default_artifact_request_for_renderer(renderer));
    remove_decision_evidence(
        &mut planning.decision_evidence,
        &[
            "no_persistent_artifact_requested",
            "shared_answer_surface",
            "tool_widget:",
            "narrow_surface_preferred",
        ],
    );
    merge_decision_evidence(
        &mut planning.decision_evidence,
        vec!["persistent_artifact_requested".to_string()],
    );
}

fn default_artifact_request_for_renderer(renderer: ChatRendererKind) -> ChatOutcomeArtifactRequest {
    canonicalize_artifact_request(ChatOutcomeArtifactRequest {
        artifact_class: match renderer {
            ChatRendererKind::Markdown | ChatRendererKind::PdfEmbed => ChatArtifactClass::Document,
            ChatRendererKind::Svg | ChatRendererKind::Mermaid => ChatArtifactClass::Visual,
            ChatRendererKind::HtmlIframe => ChatArtifactClass::Document,
            ChatRendererKind::JsxSandbox => ChatArtifactClass::InteractiveSingleFile,
            ChatRendererKind::DownloadCard => ChatArtifactClass::DownloadableFile,
            ChatRendererKind::WorkspaceSurface => ChatArtifactClass::WorkspaceProject,
            ChatRendererKind::BundleManifest => ChatArtifactClass::CompoundBundle,
        },
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::SharedArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::None,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: ChatOutcomeArtifactVerificationRequest {
            require_render: false,
            require_build: false,
            require_preview: false,
            require_export: false,
            require_diff_review: false,
        },
    })
}

fn remove_decision_evidence(target: &mut Vec<String>, removals: &[&str]) {
    target.retain(|hint| {
        !removals.iter().any(|removal| {
            hint == removal
                || (removal.ends_with(':') && hint.starts_with(*removal))
                || (removal.ends_with('*') && hint.starts_with(removal.trim_end_matches('*')))
        })
    });
}

fn apply_topology_projection_to_planning(
    planning: &mut ChatOutcomePlanningPayload,
    intent: &str,
    active_artifact_id: Option<&str>,
    confidence: f32,
) {
    apply_topology_projection_fields(planning, intent, active_artifact_id, confidence);
    let mut changed = clear_model_clarification_for_complete_specialized_frame(planning);
    if promote_conversation_to_specialized_outcome_from_typed_frame(planning) {
        changed = true;
    }
    if changed {
        apply_topology_projection_fields(planning, intent, active_artifact_id, confidence);
    }
}

fn clear_overeager_conversation_clarification(planning: &mut ChatOutcomePlanningPayload) -> bool {
    if !planning.needs_clarification
        || planning.outcome_kind != ChatOutcomeKind::Conversation
        || planning.artifact.is_some()
    {
        return false;
    }

    if planning
        .normalized_request
        .as_ref()
        .is_some_and(|frame| !chat_normalized_request_clarification_slots(frame).is_empty())
    {
        return false;
    }

    planning.needs_clarification = false;
    planning.clarification_questions.clear();
    merge_decision_evidence(
        &mut planning.decision_evidence,
        vec!["answer_with_stated_uncertainty".to_string()],
    );
    true
}

fn apply_topology_projection_fields(
    planning: &mut ChatOutcomePlanningPayload,
    intent: &str,
    active_artifact_id: Option<&str>,
    confidence: f32,
) {
    let projection = derive_chat_topology_projection(
        intent,
        active_artifact_id,
        None,
        planning.outcome_kind,
        planning.execution_strategy,
        planning.execution_mode_decision.as_ref(),
        confidence,
        planning.needs_clarification,
        &planning.clarification_questions,
        &planning.decision_evidence,
        planning.artifact.as_ref(),
    );
    planning.lane_request = projection.lane_request;
    planning.normalized_request = projection.normalized_request;
    planning.source_decision = projection.source_decision;
    planning.retained_lane_state = projection.retained_lane_state;
    planning.lane_transitions = projection.lane_transitions;
    planning.orchestration_state = projection.orchestration_state;
}

fn promote_conversation_to_specialized_outcome_from_typed_frame(
    planning: &mut ChatOutcomePlanningPayload,
) -> bool {
    if planning.outcome_kind != ChatOutcomeKind::Conversation {
        return false;
    }

    let Some(frame) = planning.normalized_request.as_ref() else {
        return false;
    };

    let widget_family = match frame {
        ChatNormalizedRequest::Weather(_) => "weather",
        ChatNormalizedRequest::Sports(_) => "sports",
        ChatNormalizedRequest::Places(_) => "places",
        ChatNormalizedRequest::Recipe(_) => "recipe",
        ChatNormalizedRequest::MessageCompose(_)
        | ChatNormalizedRequest::UserInput(_)
        | ChatNormalizedRequest::SoftwareInstall(_)
        | ChatNormalizedRequest::RuntimeAction(_) => return false,
    };

    let selected_specialized_tool = planning
        .source_decision
        .as_ref()
        .is_some_and(|selection| selection.selected_source == ChatSourceFamily::SpecializedTool);
    if !selected_specialized_tool {
        return false;
    }

    force_tool_widget_route(planning, widget_family);
    true
}

fn complete_specialized_tool_frame(planning: &ChatOutcomePlanningPayload) -> bool {
    let Some(frame) = planning.normalized_request.as_ref() else {
        return false;
    };
    if !matches!(
        frame,
        ChatNormalizedRequest::Weather(_)
            | ChatNormalizedRequest::Sports(_)
            | ChatNormalizedRequest::Places(_)
            | ChatNormalizedRequest::Recipe(_)
    ) {
        return false;
    }
    if !chat_normalized_request_clarification_slots(frame).is_empty() {
        return false;
    }
    planning
        .source_decision
        .as_ref()
        .is_some_and(|selection| selection.selected_source == ChatSourceFamily::SpecializedTool)
}

fn clear_model_clarification_for_complete_specialized_frame(
    planning: &mut ChatOutcomePlanningPayload,
) -> bool {
    if !planning.needs_clarification || !complete_specialized_tool_frame(planning) {
        return false;
    }
    planning.needs_clarification = false;
    planning.clarification_questions.clear();
    true
}

pub fn build_chat_outcome_router_prompt(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&ChatArtifactRefinementContext>,
) -> serde_json::Value {
    build_chat_outcome_router_prompt_for_runtime(
        intent,
        active_artifact_id,
        active_artifact,
        ChatRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

pub(crate) fn build_chat_outcome_router_prompt_for_runtime(
    intent: &str,
    active_artifact_id: Option<&str>,
    active_artifact: Option<&ChatArtifactRefinementContext>,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> serde_json::Value {
    if runtime_kind == ChatRuntimeProvenanceKind::RealLocalRuntime {
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
        chat_artifact_refinement_context_view(active_artifact).to_string();
    let system_content = "You are Chat's typed outcome router. Route a user request to exactly one outcome kind: conversation, tool_widget, visualizer, or artifact. Do not guess. If confidence is low, set needsClarification true. Workspace is only one artifact renderer, not the default. Artifact output must be chosen when the request should become a persistent work product. When an active artifact context is supplied, continue that artifact by default for under-specified follow-up edits instead of switching renderer families. Output JSON only.";
    let user_content = format!(
        "Request:\n{}\n\nActive artifact id: {}\n\nActive artifact context JSON:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"outcomeKind\": \"conversation\" | \"tool_widget\" | \"visualizer\" | \"artifact\",\n  \"executionStrategy\": \"single_pass\" | \"direct_author\" | \"plan_execute\" | \"micro_work_graph\" | \"adaptive_work_graph\",\n  \"confidence\": <0_to_1_float>,\n  \"needsClarification\": <boolean>,\n  \"clarificationQuestions\": [<string>],\n  \"decisionEvidence\": [<string>],\n  \"artifact\": null | {{\n    \"artifactClass\": \"document\" | \"visual\" | \"interactive_single_file\" | \"downloadable_file\" | \"workspace_project\" | \"compound_bundle\" | \"code_patch\" | \"report_bundle\",\n    \"deliverableShape\": \"single_file\" | \"file_set\" | \"workspace_project\",\n    \"renderer\": \"markdown\" | \"html_iframe\" | \"jsx_sandbox\" | \"svg\" | \"mermaid\" | \"pdf_embed\" | \"download_card\" | \"workspace_surface\" | \"bundle_manifest\",\n    \"presentationSurface\": \"inline\" | \"side_panel\" | \"overlay\" | \"tabbed_panel\",\n    \"persistence\": \"ephemeral\" | \"artifact_scoped\" | \"shared_artifact_scoped\" | \"workspace_filesystem\",\n    \"executionSubstrate\": \"none\" | \"client_sandbox\" | \"binary_generator\" | \"workspace_runtime\",\n    \"workspaceRecipeId\": null | \"react-vite\" | \"vite-static-html\",\n    \"presentationVariantId\": null | \"sport-editorial\" | \"minimal-agency\" | \"hospitality-retreat\" | \"product-launch\",\n    \"scope\": {{\n      \"targetProject\": null | <string>,\n      \"createNewWorkspace\": <boolean>,\n      \"mutationBoundary\": [<string>]\n    }},\n    \"verification\": {{\n      \"requireRender\": <boolean>,\n      \"requireBuild\": <boolean>,\n      \"requirePreview\": <boolean>,\n      \"requireExport\": <boolean>,\n      \"requireDiffReview\": <boolean>\n    }}\n  }}\n}}\nExecution strategy contracts:\n- single_pass = one bounded draft with no candidate search.\n- direct_author = direct first-pass authoring for one coherent single-document artifact; preserve the raw request and skip planner scaffolding on the first generation.\n- plan_execute = default when one planned execution unit is sufficient.\n- micro_work_graph = use when the request implies a small known work graph.\n- adaptive_work_graph = use only when the request clearly needs a mutable multi-node work graph.\nRenderer contracts:\n- markdown = a single renderable .md document.\n- html_iframe = a single self-contained .html document for browser presentation. Choose this when the final artifact should be HTML itself, such as a landing page, explainer, launch page, editorial page, or browser-native interactive document.\n- jsx_sandbox = a single .jsx source module with a default export. Choose this only when the final artifact should be JSX/React source as the work product rather than a plain HTML document.\n- svg = a single .svg visual artifact.\n- mermaid = a single .mermaid diagram source artifact.\n- pdf_embed = a document artifact that will be compiled into PDF bytes.\n- download_card = downloadable files or exports, not a primary inline document surface.\n- workspace_surface = a real multi-file workspace with supervised build/preview.\nCoherence rules:\n- html_iframe uses single_file deliverableShape and client_sandbox executionSubstrate, and may be artifactClass=document for plain authored HTML or interactive_single_file when the request truly needs browser interaction.\n- jsx_sandbox is an interactive_single_file artifact with single_file deliverableShape and client_sandbox executionSubstrate.\n- workspace_surface is the only renderer that may use workspace_project deliverableShape, workspace_runtime executionSubstrate, createNewWorkspace=true, requireBuild=true, or requirePreview=true.\n- Non-workspace artifact renderers should not request build or preview verification.\nRules:\n1) conversation is for plain reply only.\n2) tool_widget is for first-party tool display surfaces.\n3) visualizer is for ephemeral inline visuals.\n4) artifact is for persistent work products.\n5) Use workspace_surface only when a real multi-file workspace and preview runtime are required.\n6) Prefer direct_author for a fresh coherent single-file document ask that the model can author directly, such as markdown, html_iframe, svg, mermaid, or pdf_embed; otherwise prefer plan_execute unless the request is trivial enough for single_pass, small-graph enough for micro_work_graph, or clearly mutable enough for adaptive_work_graph.\n7) Treat explicit medium-plus-deliverable requests as sufficiently specified artifact work. If the user already asked for an HTML artifact, landing page, launch page, editorial page, markdown document, SVG concept, Mermaid diagram, PDF artifact, downloadable bundle, or workspace project, do not ask clarification merely to restate that same deliverable form.\n8) For example, \"Create an interactive HTML artifact for an AI tools editorial launch page\" is already an artifact request for html_iframe, not a clarification request.\n9) When active artifact context JSON is not null and the request is a follow-up refinement, patch or branch the current artifact by default instead of switching renderer, artifactClass, or deliverableShape unless the user explicitly asks for a different deliverable form.\n10) Under-specified follow-up requests should continue the active artifact rather than restarting as a new artifact kind.\n11) For tool_widget, include exactly one decisionEvidence entry of tool_widget:weather | tool_widget:recipe | tool_widget:sports | tool_widget:places | tool_widget:user_input.\n12) Include currentness_override when the request requires fresh or up-to-date information.\n13) Include workspace_grounding_required and coding_workspace_context when the answer should come from the current repo or workspace.\n14) Include downloadable_export_requested for download_card or bundle_manifest artifacts, plus download_format:<ext> when the requested export format is explicit.\n15) Include shared_answer_surface for inline conversation answers and narrow_surface_preferred when you choose a tool_widget.\n16) Do not use lexical fallbacks or benchmark phrase maps.\n17) When uncertainty remains about a required missing constraint, keep confidence low and ask clarification.",
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
    request: ChatOutcomeArtifactRequest,
) -> ChatOutcomeArtifactRequest {
    let renderer = request.renderer;
    let artifact_class = match renderer {
        ChatRendererKind::Markdown | ChatRendererKind::PdfEmbed => ChatArtifactClass::Document,
        ChatRendererKind::Svg | ChatRendererKind::Mermaid => ChatArtifactClass::Visual,
        ChatRendererKind::HtmlIframe => match request.artifact_class {
            ChatArtifactClass::Document | ChatArtifactClass::InteractiveSingleFile => {
                request.artifact_class
            }
            _ => ChatArtifactClass::Document,
        },
        ChatRendererKind::JsxSandbox => ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::DownloadCard => ChatArtifactClass::DownloadableFile,
        ChatRendererKind::WorkspaceSurface => ChatArtifactClass::WorkspaceProject,
        ChatRendererKind::BundleManifest => match request.artifact_class {
            ChatArtifactClass::CompoundBundle
            | ChatArtifactClass::ReportBundle
            | ChatArtifactClass::CodePatch => request.artifact_class,
            _ => ChatArtifactClass::CompoundBundle,
        },
    };
    let deliverable_shape = match renderer {
        ChatRendererKind::WorkspaceSurface => ChatArtifactDeliverableShape::WorkspaceProject,
        ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest => {
            ChatArtifactDeliverableShape::FileSet
        }
        _ => ChatArtifactDeliverableShape::SingleFile,
    };
    let presentation_surface = match renderer {
        ChatRendererKind::WorkspaceSurface => ChatPresentationSurface::TabbedPanel,
        _ => ChatPresentationSurface::SidePanel,
    };
    let persistence = match renderer {
        ChatRendererKind::WorkspaceSurface => ChatArtifactPersistenceMode::WorkspaceFilesystem,
        ChatRendererKind::BundleManifest => ChatArtifactPersistenceMode::ArtifactScoped,
        _ => ChatArtifactPersistenceMode::SharedArtifactScoped,
    };
    let execution_substrate = match renderer {
        ChatRendererKind::WorkspaceSurface => ChatExecutionSubstrate::WorkspaceRuntime,
        ChatRendererKind::PdfEmbed => ChatExecutionSubstrate::BinaryGenerator,
        ChatRendererKind::HtmlIframe
        | ChatRendererKind::JsxSandbox
        | ChatRendererKind::Svg
        | ChatRendererKind::Mermaid => ChatExecutionSubstrate::ClientSandbox,
        _ => ChatExecutionSubstrate::None,
    };
    let scope = ChatOutcomeArtifactScope {
        target_project: request.scope.target_project,
        create_new_workspace: renderer == ChatRendererKind::WorkspaceSurface,
        mutation_boundary: if request.scope.mutation_boundary.is_empty() {
            vec!["artifact".to_string()]
        } else {
            request.scope.mutation_boundary
        },
    };
    let verification = ChatOutcomeArtifactVerificationRequest {
        require_render: request.verification.require_render,
        require_build: renderer == ChatRendererKind::WorkspaceSurface,
        require_preview: renderer == ChatRendererKind::WorkspaceSurface,
        require_export: request.verification.require_export,
        require_diff_review: if renderer == ChatRendererKind::WorkspaceSurface {
            request.verification.require_diff_review
        } else {
            false
        },
    };

    ChatOutcomeArtifactRequest {
        artifact_class,
        deliverable_shape,
        renderer,
        presentation_surface,
        persistence,
        execution_substrate,
        workspace_recipe_id: if renderer == ChatRendererKind::WorkspaceSurface {
            request.workspace_recipe_id
        } else {
            None
        },
        presentation_variant_id: if matches!(
            renderer,
            ChatRendererKind::HtmlIframe
                | ChatRendererKind::JsxSandbox
                | ChatRendererKind::WorkspaceSurface
        ) {
            request.presentation_variant_id
        } else {
            None
        },
        scope,
        verification,
    }
}

fn merge_decision_evidence(target: &mut Vec<String>, incoming: Vec<String>) {
    for hint in incoming {
        if target.iter().any(|existing| existing == &hint) {
            continue;
        }
        target.push(hint);
    }
}

fn default_decision_evidence_for_planning(planning: &ChatOutcomePlanningPayload) -> Vec<String> {
    let mut hints = Vec::<String>::new();
    match planning.outcome_kind {
        ChatOutcomeKind::Artifact => {
            hints.push("persistent_artifact_requested".to_string());
            if let Some(artifact) = planning.artifact.as_ref() {
                if matches!(
                    artifact.renderer,
                    ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest
                ) {
                    hints.push("downloadable_export_requested".to_string());
                }
            }
        }
        _ => {
            hints.push("no_persistent_artifact_requested".to_string());
            if planning.outcome_kind == ChatOutcomeKind::Conversation {
                hints.push("shared_answer_surface".to_string());
            }
        }
    }

    if planning.outcome_kind == ChatOutcomeKind::ToolWidget
        && planning
            .decision_evidence
            .iter()
            .any(|hint| hint.starts_with("tool_widget:"))
    {
        hints.push("narrow_surface_preferred".to_string());
    }

    hints
}

pub fn parse_chat_outcome_planning_payload(
    raw: &str,
) -> Result<ChatOutcomePlanningPayload, String> {
    let mut value = parse_chat_json_object_value(
        raw,
        "Chat outcome planning output missing JSON payload",
        "Failed to parse Chat outcome planning payload",
    )?;
    normalize_chat_outcome_planning_value(&mut value);
    serde_json::from_value::<ChatOutcomePlanningPayload>(value)
        .map_err(|error| format!("Failed to parse Chat outcome planning payload: {}", error))
}
