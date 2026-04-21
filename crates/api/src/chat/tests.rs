use super::generation::{
    apply_chat_swarm_patch_envelope,
    build_chat_artifact_direct_author_continuation_prompt_for_runtime,
    build_chat_artifact_direct_author_prompt_for_runtime,
    build_chat_artifact_materialization_prompt_for_runtime,
    evaluate_candidate_render_with_fallback, render_eval_timeout_for_runtime,
    render_evaluation_required, requested_follow_up_pass,
    validate_swarm_generated_artifact_payload, ChatArtifactPatchEnvelope,
    ChatArtifactPatchOperation, ChatArtifactPatchOperationKind,
};
use super::planning::{
    build_chat_artifact_brief_field_repair_prompt,
    build_chat_artifact_brief_prompt_for_runtime, build_chat_outcome_router_prompt_for_runtime,
    canonicalize_chat_artifact_brief_for_request, validate_chat_artifact_brief_against_request,
};
use super::validation::candidate_generation_config;
use super::*;
use crate::vm::inference::InferenceRuntime;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{
    ChatArtifactDeliverableShape, ChatArtifactPersistenceMode, ChatExecutionStrategy,
    ChatExecutionSubstrate, ChatOutcomeArtifactScope, ChatOutcomeArtifactVerificationRequest,
    ChatPresentationSurface, ChatRuntimeProvenance, ChatRuntimeProvenanceKind,
};
use ioi_types::error::VmError;
use std::future::Future;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::mpsc::Sender;
use zip::ZipArchive;

mod artifact_contract;
mod direct_author;
mod payload_validation;
mod planning_and_routing;
mod swarm_plans;

pub(super) use artifact_contract::{
    chat_test_candidate_summary, chat_test_render_capture, chat_test_render_evaluation,
    chat_test_validation, ChatPassingRenderEvaluator,
};

fn decode_chat_test_prompt(input_context: &[u8]) -> String {
    let raw_prompt = String::from_utf8_lossy(input_context);
    serde_json::from_slice::<Vec<serde_json::Value>>(input_context)
        .ok()
        .map(|messages| {
            messages
                .into_iter()
                .filter_map(|message| {
                    message
                        .get("content")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_string)
                })
                .collect::<Vec<_>>()
                .join("\n\n")
        })
        .filter(|decoded| !decoded.is_empty())
        .unwrap_or_else(|| raw_prompt.to_string())
}

fn zip_entry_names_from_base64_body(body: &str) -> Vec<String> {
    let bytes = STANDARD.decode(body.trim()).expect("base64 zip payload");
    let mut archive = ZipArchive::new(Cursor::new(bytes)).expect("zip archive");
    let mut names = Vec::new();
    for index in 0..archive.len() {
        names.push(
            archive
                .by_index(index)
                .expect("zip entry")
                .name()
                .to_string(),
        );
    }
    names.sort();
    names
}

fn zip_entry_text_from_base64_body(body: &str, entry_name: &str) -> String {
    let bytes = STANDARD.decode(body.trim()).expect("base64 zip payload");
    let mut archive = ZipArchive::new(Cursor::new(bytes)).expect("zip archive");
    let mut entry = archive.by_name(entry_name).expect("named zip entry");
    let mut text = String::new();
    entry.read_to_string(&mut text).expect("utf8 zip entry");
    text
}

fn with_modal_first_html_env<T>(f: impl FnOnce() -> T) -> T {
    with_chat_modal_first_html_override(true, f)
}

async fn with_modal_first_html_env_async<T, F>(f: impl FnOnce() -> F) -> T
where
    F: Future<Output = T>,
{
    with_chat_modal_first_html_override_async(true, f).await
}

fn request_for(
    artifact_class: ChatArtifactClass,
    renderer: ChatRendererKind,
) -> ChatOutcomeArtifactRequest {
    ChatOutcomeArtifactRequest {
        artifact_class,
        deliverable_shape: if renderer == ChatRendererKind::WorkspaceSurface {
            ChatArtifactDeliverableShape::WorkspaceProject
        } else if renderer == ChatRendererKind::BundleManifest {
            ChatArtifactDeliverableShape::FileSet
        } else {
            ChatArtifactDeliverableShape::SingleFile
        },
        renderer,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: if renderer == ChatRendererKind::WorkspaceSurface {
            ChatArtifactPersistenceMode::WorkspaceFilesystem
        } else {
            ChatArtifactPersistenceMode::ArtifactScoped
        },
        execution_substrate: match renderer {
            ChatRendererKind::WorkspaceSurface => ChatExecutionSubstrate::WorkspaceRuntime,
            ChatRendererKind::PdfEmbed => ChatExecutionSubstrate::BinaryGenerator,
            ChatRendererKind::JsxSandbox
            | ChatRendererKind::HtmlIframe
            | ChatRendererKind::Svg
            | ChatRendererKind::Mermaid => ChatExecutionSubstrate::ClientSandbox,
            _ => ChatExecutionSubstrate::None,
        },
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: ChatOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: renderer == ChatRendererKind::WorkspaceSurface,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: ChatOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: renderer == ChatRendererKind::WorkspaceSurface,
            require_preview: renderer == ChatRendererKind::WorkspaceSurface,
            require_export: true,
            require_diff_review: false,
        },
    }
}

async fn planned_prepared_context_with_runtime_plan(
    runtime_plan: &ChatArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
) -> ChatArtifactPlanningContext {
    let brief = plan_chat_artifact_brief_with_runtime(
        runtime_plan.planning_runtime.clone(),
        title,
        intent,
        request,
        refinement,
    )
    .await
    .expect("prepared context brief planning should succeed in tests");

    derive_chat_artifact_prepared_context(
        request,
        &brief,
        refinement.and_then(|context| context.blueprint.clone()),
        refinement.and_then(|context| context.artifact_ir.clone()),
        refinement
            .map(|context| context.selected_skills.clone())
            .unwrap_or_default(),
        refinement
            .map(|context| context.retrieved_exemplars.clone())
            .unwrap_or_default(),
        Vec::new(),
    )
}

fn sample_html_brief() -> ChatArtifactBrief {
    ChatArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "inspect the rollout evidence".to_string(),
        subject_domain: "dog shampoo launch".to_string(),
        artifact_thesis: "Explain the launch through evidence-rich comparison views.".to_string(),
        required_concepts: vec![
            "product rollout".to_string(),
            "customer satisfaction".to_string(),
            "usage statistics".to_string(),
        ],
        required_interactions: vec![
            "view switching".to_string(),
            "detail comparison".to_string(),
        ],
        visual_tone: vec!["grounded".to_string()],
        factual_anchors: vec!["customer feedback".to_string()],
        style_directives: vec!["clear hierarchy".to_string()],
        reference_hints: vec!["ingredient analysis".to_string()],
        query_profile: Some(ChatArtifactQueryProfile {
            content_goals: vec![
                required_content_goal(
                    ChatArtifactContentGoalKind::Explain,
                    "Explain the rollout evidence clearly.",
                ),
                required_content_goal(
                    ChatArtifactContentGoalKind::Compare,
                    "Keep comparison-ready evidence visible.",
                ),
            ],
            interaction_goals: vec![
                required_interaction_goal(
                    ChatArtifactInteractionGoalKind::StateSwitch,
                    "Switch between authored evidence states.",
                ),
                required_interaction_goal(
                    ChatArtifactInteractionGoalKind::DetailInspect,
                    "Inspect evidence details in a visible response region.",
                ),
            ],
            evidence_goals: vec![
                required_evidence_goal(
                    ChatArtifactEvidenceGoalKind::PrimarySurface,
                    "Keep primary rollout evidence visible on first paint.",
                ),
                required_evidence_goal(
                    ChatArtifactEvidenceGoalKind::ComparisonSurface,
                    "Keep a comparison evidence surface available on first paint.",
                ),
            ],
            presentation_constraints: vec![
                required_presentation_constraint(
                    ChatArtifactPresentationConstraintKind::FirstPaintEvidence,
                    "Populate the first paint with real evidence.",
                ),
                required_presentation_constraint(
                    ChatArtifactPresentationConstraintKind::ResponseRegion,
                    "Keep a visible response region on first paint.",
                ),
            ],
        }),
    }
}

fn sample_quantum_explainer_brief() -> ChatArtifactBrief {
    ChatArtifactBrief {
        audience: "curious learners".to_string(),
        job_to_be_done:
            "understand quantum computing concepts through interactive demonstrations"
                .to_string(),
        subject_domain: "quantum computing fundamentals".to_string(),
        artifact_thesis:
            "Explain superposition, entanglement, and gate transforms through visible state changes."
                .to_string(),
        required_concepts: vec![
            "superposition".to_string(),
            "entanglement".to_string(),
            "measurement probabilities".to_string(),
            "gate transforms".to_string(),
        ],
        required_interactions: vec![
            "state manipulation".to_string(),
            "detail inspection".to_string(),
            "sequence browsing".to_string(),
        ],
        visual_tone: vec!["editorial".to_string(), "technical".to_string()],
        factual_anchors: vec![
            "qubit state examples".to_string(),
            "measurement outcomes".to_string(),
        ],
        style_directives: vec![
            "clear hierarchy".to_string(),
            "strong visual labeling".to_string(),
        ],
        reference_hints: vec![
            "state diagrams".to_string(),
            "distribution comparisons".to_string(),
        ],
        query_profile: Some(ChatArtifactQueryProfile {
            content_goals: vec![
                required_content_goal(
                    ChatArtifactContentGoalKind::Explain,
                    "Explain the key quantum concepts clearly.",
                ),
                required_content_goal(
                    ChatArtifactContentGoalKind::Compare,
                    "Compare visible quantum states and outcomes.",
                ),
            ],
            interaction_goals: vec![
                required_interaction_goal(
                    ChatArtifactInteractionGoalKind::StateAdjust,
                    "Adjust visible state controls.",
                ),
                required_interaction_goal(
                    ChatArtifactInteractionGoalKind::DetailInspect,
                    "Inspect visible state details.",
                ),
                required_interaction_goal(
                    ChatArtifactInteractionGoalKind::SequenceBrowse,
                    "Progress through staged quantum examples.",
                ),
            ],
            evidence_goals: vec![
                required_evidence_goal(
                    ChatArtifactEvidenceGoalKind::PrimarySurface,
                    "Keep the primary state surface visible.",
                ),
                required_evidence_goal(
                    ChatArtifactEvidenceGoalKind::SupportingSurface,
                    "Support the explanation with visible labeled evidence.",
                ),
            ],
            presentation_constraints: vec![
                required_presentation_constraint(
                    ChatArtifactPresentationConstraintKind::FirstPaintEvidence,
                    "Populate the first paint with working state evidence.",
                ),
                required_presentation_constraint(
                    ChatArtifactPresentationConstraintKind::ResponseRegion,
                    "Keep a visible response region on first paint.",
                ),
            ],
        }),
    }
}

fn sample_quantum_markdown_brief() -> ChatArtifactBrief {
    ChatArtifactBrief {
        audience: "curious readers".to_string(),
        job_to_be_done: "understand quantum computing through a concise markdown explainer"
            .to_string(),
        subject_domain: "quantum computing fundamentals".to_string(),
        artifact_thesis:
            "Explain qubits, superposition, interference, and hardware limits in a compact document."
                .to_string(),
        required_concepts: vec![
            "qubits".to_string(),
            "superposition".to_string(),
            "interference".to_string(),
            "hardware limits".to_string(),
        ],
        required_interactions: Vec::new(),
        visual_tone: vec!["editorial".to_string(), "clear".to_string()],
        factual_anchors: vec![
            "measurement outcomes".to_string(),
            "error rates".to_string(),
        ],
        style_directives: vec!["concise hierarchy".to_string()],
        reference_hints: vec!["explainer memo".to_string()],
        query_profile: Some(ChatArtifactQueryProfile {
            content_goals: vec![
                required_content_goal(
                    ChatArtifactContentGoalKind::Summary,
                    "Summarize the quantum concepts clearly.",
                ),
                required_content_goal(
                    ChatArtifactContentGoalKind::Explain,
                    "Explain the evidence behind the concepts.",
                ),
            ],
            interaction_goals: Vec::new(),
            evidence_goals: vec![required_evidence_goal(
                ChatArtifactEvidenceGoalKind::SupportingSurface,
                "Support the document with grounded evidence.",
            )],
            presentation_constraints: vec![required_presentation_constraint(
                ChatArtifactPresentationConstraintKind::SemanticStructure,
                "Keep the document semantically structured.",
            )],
        }),
    }
}

fn sample_complex_mission_control_brief() -> ChatArtifactBrief {
    ChatArtifactBrief {
        audience: "launch operators".to_string(),
        job_to_be_done:
            "coordinate a post-quantum migration through a dense mission-control style artifact"
                .to_string(),
        subject_domain: "post-quantum migration program".to_string(),
        artifact_thesis:
            "Guide operators through rollout phases, risk posture, cutover decisions, and incident response in one interactive artifact."
                .to_string(),
        required_concepts: vec![
            "fleet rollout phases".to_string(),
            "cryptography inventory".to_string(),
            "vendor readiness".to_string(),
            "cutover decision points".to_string(),
            "owner handoffs".to_string(),
            "incident fallback playbook".to_string(),
        ],
        required_interactions: vec![
            "phase switching".to_string(),
            "risk drilldown".to_string(),
            "owner handoff comparison".to_string(),
            "cutover simulation".to_string(),
        ],
        visual_tone: vec![
            "operator-grade".to_string(),
            "dense".to_string(),
            "technical".to_string(),
        ],
        factual_anchors: vec![
            "fleet readiness snapshot".to_string(),
            "handoff ownership".to_string(),
            "rollback thresholds".to_string(),
        ],
        style_directives: vec![
            "dense but readable".to_string(),
            "slate mission control".to_string(),
        ],
        reference_hints: vec![
            "control room dashboard".to_string(),
            "rollout workbook".to_string(),
        ],
        query_profile: Some(ChatArtifactQueryProfile {
            content_goals: vec![
                required_content_goal(
                    ChatArtifactContentGoalKind::Orient,
                    "Orient operators to the migration program immediately.",
                ),
                required_content_goal(
                    ChatArtifactContentGoalKind::Compare,
                    "Compare phases, risks, and owner handoffs.",
                ),
            ],
            interaction_goals: vec![
                required_interaction_goal(
                    ChatArtifactInteractionGoalKind::StateSwitch,
                    "Switch between operator views.",
                ),
                required_interaction_goal(
                    ChatArtifactInteractionGoalKind::DetailInspect,
                    "Inspect detailed operator evidence inline.",
                ),
                required_interaction_goal(
                    ChatArtifactInteractionGoalKind::StateAdjust,
                    "Adjust cutover simulation state.",
                ),
            ],
            evidence_goals: vec![
                required_evidence_goal(
                    ChatArtifactEvidenceGoalKind::PrimarySurface,
                    "Keep mission control evidence visible on first paint.",
                ),
                required_evidence_goal(
                    ChatArtifactEvidenceGoalKind::ComparisonSurface,
                    "Keep alternate evidence views available on first paint.",
                ),
            ],
            presentation_constraints: vec![
                required_presentation_constraint(
                    ChatArtifactPresentationConstraintKind::FirstPaintEvidence,
                    "Populate the first paint with real operator evidence.",
                ),
                required_presentation_constraint(
                    ChatArtifactPresentationConstraintKind::ResponseRegion,
                    "Keep a visible response region on first paint.",
                ),
            ],
        }),
    }
}

fn required_interaction_goal(
    kind: ChatArtifactInteractionGoalKind,
    summary: &str,
) -> ChatArtifactInteractionGoal {
    ChatArtifactInteractionGoal {
        kind,
        summary: summary.to_string(),
        required: true,
    }
}

fn required_content_goal(
    kind: ChatArtifactContentGoalKind,
    summary: &str,
) -> ChatArtifactContentGoal {
    ChatArtifactContentGoal {
        kind,
        summary: summary.to_string(),
        required: true,
    }
}

fn required_evidence_goal(
    kind: ChatArtifactEvidenceGoalKind,
    summary: &str,
) -> ChatArtifactEvidenceGoal {
    ChatArtifactEvidenceGoal {
        kind,
        summary: summary.to_string(),
        required: true,
    }
}

fn required_presentation_constraint(
    kind: ChatArtifactPresentationConstraintKind,
    summary: &str,
) -> ChatArtifactPresentationConstraint {
    ChatArtifactPresentationConstraint {
        kind,
        summary: summary.to_string(),
        required: true,
    }
}

#[test]
fn html_swarm_semantic_conflict_rejects_cross_boundary_patch() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let mut payload = ChatGeneratedArtifactPayload {
        summary: "Seed".to_string(),
        notes: Vec::new(),
        files: vec![ChatGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: "<!doctype html><html><body><!-- STUDIO_REGION_START:section:intro --><section>Old body</section><!-- STUDIO_REGION_END:section:intro --></body></html>".to_string(),
        }],
    };
    let work_item = ChatArtifactWorkItem {
        id: "section-1".to_string(),
        title: "Section 1".to_string(),
        role: ChatArtifactWorkerRole::SectionContent,
        summary: "Own the intro section.".to_string(),
        spawned_from_id: None,
        read_paths: vec!["index.html".to_string()],
        write_paths: vec!["index.html".to_string()],
        write_regions: vec!["section:intro".to_string()],
        lease_requirements: vec![
            shared_read_lease_for_path("index.html"),
            exclusive_write_lease_for_region("section:intro"),
        ],
        acceptance_criteria: vec!["Stay inside the intro region.".to_string()],
        dependency_ids: vec!["skeleton".to_string()],
        blocked_on_ids: Vec::new(),
        verification_policy: Some(SwarmVerificationPolicy::Normal),
        retry_budget: Some(0),
        status: ChatArtifactWorkItemStatus::Pending,
    };
    let envelope = ChatArtifactPatchEnvelope {
        summary: Some("Bad section patch".to_string()),
        notes: Vec::new(),
        operations: vec![ChatArtifactPatchOperation {
            kind: ChatArtifactPatchOperationKind::ReplaceFile,
            path: "index.html".to_string(),
            region_id: None,
            mime: None,
            role: None,
            renderable: None,
            downloadable: None,
            encoding: None,
            body: Some(
                "<script>document.body.dataset.bad='true';</script><section>Wrong boundary</section>"
                    .to_string(),
            ),
        }],
    };

    let (patch_receipt, merge_receipt) =
        apply_chat_swarm_patch_envelope(&request, &mut payload, &work_item, &envelope)
            .expect("semantic conflict should surface as a bounded rejection");

    assert_eq!(patch_receipt.status, ChatArtifactWorkItemStatus::Rejected);
    assert_eq!(merge_receipt.status, ChatArtifactWorkItemStatus::Rejected);
    assert!(patch_receipt
        .failure
        .as_deref()
        .is_some_and(|failure| failure.contains("semantic ownership boundary")));
    assert!(merge_receipt
        .rejected_reason
        .as_deref()
        .is_some_and(|reason| reason.contains("semantic ownership boundary")));
    assert!(payload.files[0].body.contains("Old body"));
}

#[test]
fn validate_swarm_generated_artifact_payload_repairs_default_primary_renderable_flag() {
    let request = request_for(
        ChatArtifactClass::InteractiveSingleFile,
        ChatRendererKind::HtmlIframe,
    );
    let payload = ChatGeneratedArtifactPayload {
        summary: "Interactive HTML artifact".to_string(),
        notes: Vec::new(),
        files: vec![ChatGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: false,
            downloadable: true,
            encoding: None,
            body: "<!doctype html><html><body><main><header><h1>Renderable shell</h1><div class=\"controls\"><button type=\"button\" data-view=\"risk\" aria-pressed=\"true\">Risk</button><button type=\"button\" data-view=\"rollback\" aria-pressed=\"false\">Rollback</button></div></header><section id=\"risk-panel\"><h2>Risk detail</h2><p id=\"detail-copy\">Inspect cryptography risk before cutover.</p></section><section id=\"rollback-panel\" hidden><h2>Rollback</h2><p>Rollback playbook is ready if launch conditions fail.</p></section><section><h2>Operator summary</h2><p>Compare phases, inspect risk, and confirm rollback readiness.</p></section></main><script>document.querySelectorAll('[data-view]').forEach((button)=>button.addEventListener('click',()=>{const isRisk=button.dataset.view==='risk';document.getElementById('risk-panel').hidden=!isRisk;document.getElementById('rollback-panel').hidden=isRisk;document.getElementById('detail-copy').textContent=isRisk?'Inspect cryptography risk before cutover.':'Rollback playbook is visible.';document.querySelectorAll('[data-view]').forEach((candidate)=>candidate.setAttribute('aria-pressed', String(candidate===button)));}));</script></body></html>".to_string(),
        }],
    };

    let repaired = validate_swarm_generated_artifact_payload(&payload, &request)
        .expect("default HTML primary file should be normalized before validation");

    let primary = repaired
        .files
        .iter()
        .find(|file| file.path == "index.html")
        .expect("normalized primary file");
    assert_eq!(primary.role, ChatArtifactFileRole::Primary);
    assert!(primary.renderable);
    assert!(!primary.downloadable);
    assert_eq!(
        primary.encoding,
        Some(ChatGeneratedArtifactEncoding::Utf8)
    );
}
