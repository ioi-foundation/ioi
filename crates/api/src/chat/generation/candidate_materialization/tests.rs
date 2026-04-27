use super::{
    direct_author_fast_runtime_sanity_enabled, render_sanity_block_reason,
    render_sanity_repair_reason, ChatArtifactAcceptanceObligation,
    ChatArtifactAcceptanceObligationStatus, ChatArtifactExecutionWitness,
    ChatArtifactExecutionWitnessStatus, ChatArtifactRenderAcceptancePolicy,
    ChatArtifactRenderEvaluation, ChatArtifactRenderFinding, ChatArtifactRenderFindingSeverity,
    ChatArtifactRenderObservation, ChatArtifactRenderPolicyMode, ChatRuntimeProvenanceKind,
};
use ioi_types::app::{
    ChatArtifactClass, ChatArtifactDeliverableShape, ChatArtifactPersistenceMode,
    ChatExecutionSubstrate, ChatOutcomeArtifactRequest, ChatOutcomeArtifactScope,
    ChatOutcomeArtifactVerificationRequest, ChatPresentationSurface, ChatRendererKind,
};

fn sample_request(artifact_class: ChatArtifactClass) -> ChatOutcomeArtifactRequest {
    ChatOutcomeArtifactRequest {
        artifact_class,
        deliverable_shape: ChatArtifactDeliverableShape::SingleFile,
        renderer: ChatRendererKind::HtmlIframe,
        presentation_surface: ChatPresentationSurface::SidePanel,
        persistence: ChatArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: ChatExecutionSubstrate::ClientSandbox,
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
    }
}

fn warning_only_primary_ready_evaluation() -> ChatArtifactRenderEvaluation {
    ChatArtifactRenderEvaluation {
        supported: true,
        first_paint_captured: true,
        interaction_capture_attempted: true,
        captures: Vec::new(),
        observation: Some(ChatArtifactRenderObservation {
            primary_region_present: true,
            first_paint_visible_text_chars: 160,
            mobile_visible_text_chars: 120,
            semantic_region_count: 4,
            evidence_surface_count: 1,
            response_region_count: 1,
            actionable_affordance_count: 4,
            active_affordance_count: 1,
            runtime_error_count: 0,
            interaction_state_changed: true,
        }),
        acceptance_policy: Some(ChatArtifactRenderAcceptancePolicy {
            mode: ChatArtifactRenderPolicyMode::Balanced,
            minimum_first_paint_text_chars: 60,
            minimum_semantic_regions: 3,
            minimum_evidence_surfaces: 1,
            minimum_actionable_affordances: 2,
            blocked_score_threshold: 9,
            primary_view_score_threshold: 18,
            require_primary_region: true,
            require_response_region_when_interactive: true,
            require_state_change_when_interactive: true,
        }),
        layout_density_score: 4,
        spacing_alignment_score: 4,
        typography_contrast_score: 4,
        visual_hierarchy_score: 4,
        blueprint_consistency_score: 3,
        overall_score: 17,
        findings: vec![ChatArtifactRenderFinding {
            code: "minor_spacing".to_string(),
            severity: ChatArtifactRenderFindingSeverity::Warning,
            summary: "Spacing could be tightened.".to_string(),
        }],
        acceptance_obligations: vec![ChatArtifactAcceptanceObligation {
            obligation_id: "interactive_state_change".to_string(),
            family: "interaction".to_string(),
            required: true,
            status: ChatArtifactAcceptanceObligationStatus::Passed,
            summary: "Interactive state changed.".to_string(),
            detail: None,
            witness_ids: vec!["witness-1".to_string()],
        }],
        execution_witnesses: vec![ChatArtifactExecutionWitness {
            witness_id: "witness-1".to_string(),
            obligation_id: Some("interactive_state_change".to_string()),
            action_kind: "click".to_string(),
            status: ChatArtifactExecutionWitnessStatus::Passed,
            summary: "Primary control updated shared state.".to_string(),
            detail: None,
            selector: Some("#toggle".to_string()),
            console_errors: vec![
                "ResizeObserver loop completed with undelivered notifications.".to_string(),
            ],
            state_changed: true,
        }],
        summary: "Captured first paint and interaction with minor polish warnings.".to_string(),
    }
}

#[test]
fn warning_only_primary_ready_render_eval_does_not_block() {
    let evaluation = warning_only_primary_ready_evaluation();

    assert_eq!(render_sanity_block_reason(Some(&evaluation)), None);
}

#[test]
fn warning_only_primary_ready_render_eval_does_not_request_repair() {
    let evaluation = warning_only_primary_ready_evaluation();

    assert_eq!(render_sanity_repair_reason(Some(&evaluation)), None);
}

#[test]
fn fast_runtime_sanity_skips_plain_document_html_on_local_runtime() {
    let request = sample_request(ChatArtifactClass::Document);

    assert!(!direct_author_fast_runtime_sanity_enabled(
        &request,
        ChatRuntimeProvenanceKind::RealLocalRuntime
    ));
}

#[test]
fn fast_runtime_sanity_keeps_interactive_html_on_local_runtime() {
    let request = sample_request(ChatArtifactClass::InteractiveSingleFile);

    assert!(direct_author_fast_runtime_sanity_enabled(
        &request,
        ChatRuntimeProvenanceKind::RealLocalRuntime
    ));
}

#[test]
fn fast_runtime_sanity_respects_explicit_render_verification_for_document_html() {
    let mut request = sample_request(ChatArtifactClass::Document);
    request.verification.require_render = true;

    assert!(direct_author_fast_runtime_sanity_enabled(
        &request,
        ChatRuntimeProvenanceKind::RealLocalRuntime
    ));
}
