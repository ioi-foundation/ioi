use super::*;
use ioi_api::studio::{
    StudioArtifactAcceptanceTargets, StudioArtifactAccessibilityPlan,
    StudioArtifactCandidateConvergenceTrace, StudioArtifactComponentPlanEntry,
    StudioArtifactDesignSystem, StudioArtifactOutputOrigin, StudioArtifactSkillNeed,
    StudioArtifactSkillNeedKind, StudioArtifactSkillNeedPriority,
};

fn sample_blueprint() -> StudioArtifactBlueprint {
    StudioArtifactBlueprint {
        version: 1,
        renderer: StudioRendererKind::HtmlIframe,
        narrative_arc: "comparison_story".to_string(),
        section_plan: vec![],
        interaction_plan: vec![],
        evidence_plan: vec![],
        design_system: StudioArtifactDesignSystem {
            color_strategy: "editorial".to_string(),
            typography_strategy: "display+mono".to_string(),
            density: "medium".to_string(),
            motion_style: "restrained".to_string(),
            emphasis_modes: vec!["contrast-led".to_string(), "detail-rail".to_string()],
        },
        component_plan: vec![StudioArtifactComponentPlanEntry {
            id: "component-1".to_string(),
            component_family: "tabbed_evidence_rail".to_string(),
            role: "evidence".to_string(),
            section_ids: vec!["section-1".to_string()],
            interaction_ids: vec!["interaction-1".to_string()],
        }],
        accessibility_plan: StudioArtifactAccessibilityPlan {
            obligations: vec!["keyboard".to_string()],
            focus_order: vec![],
            aria_expectations: vec![],
        },
        acceptance_targets: StudioArtifactAcceptanceTargets {
            minimum_section_count: 2,
            minimum_interactive_regions: 1,
            require_first_paint_evidence: true,
            require_persistent_detail_region: true,
            require_distinct_typography: true,
            require_keyboard_affordances: true,
        },
        scaffold_family: "comparison_story".to_string(),
        variation_strategy: "editorial".to_string(),
        skill_needs: vec![StudioArtifactSkillNeed {
            kind: StudioArtifactSkillNeedKind::VisualArtDirection,
            priority: StudioArtifactSkillNeedPriority::Required,
            rationale: "Need strong art direction.".to_string(),
        }],
    }
}

fn sample_selected_skill() -> StudioArtifactSelectedSkill {
    StudioArtifactSelectedSkill {
        skill_hash: "a".repeat(64),
        name: "frontend-skill".to_string(),
        description: "Frontend design".to_string(),
        lifecycle_state: "published".to_string(),
        source_type: "skill".to_string(),
        reliability_bps: 9400,
        semantic_score_bps: 9300,
        adjusted_score_bps: 9500,
        relative_path: Some("skills/frontend/SKILL.md".to_string()),
        matched_need_ids: vec!["visual_art_direction-1".to_string()],
        matched_need_kinds: vec![StudioArtifactSkillNeedKind::VisualArtDirection],
        match_rationale: "Structural visual match.".to_string(),
        guidance_markdown: Some("Use a strong visual hierarchy.".to_string()),
    }
}

fn sample_validation() -> StudioArtifactValidationResult {
    StudioArtifactValidationResult {
        classification: StudioArtifactValidationStatus::Repairable,
        request_faithfulness: 4,
        concept_coverage: 4,
        interaction_relevance: 4,
        layout_coherence: 4,
        visual_hierarchy: 4,
        completeness: 4,
        generic_shell_detected: false,
        trivial_shell_detected: false,
        deserves_primary_artifact_view: true,
        patched_existing_artifact: Some(true),
        continuity_revision_ux: Some(4),
        issue_classes: vec!["first_paint_density".to_string()],
        repair_hints: vec!["Add a richer first-paint evidence rail.".to_string()],
        strengths: vec!["Strong layout".to_string()],
        blocked_reasons: vec![],
        file_findings: vec!["index.html keeps the detail panel visible.".to_string()],
        aesthetic_verdict: "Good".to_string(),
        interaction_verdict: "Repairable".to_string(),
        truthfulness_warnings: vec!["Needs more visible evidence.".to_string()],
        recommended_next_pass: Some("repair_loop".to_string()),
        strongest_contradiction: Some("Needs more visible evidence.".to_string()),
        rationale: "Repairable with a stronger first paint.".to_string(),
    }
}

fn sample_candidate_summary(
    validation: &StudioArtifactValidationResult,
) -> StudioArtifactCandidateSummary {
    StudioArtifactCandidateSummary {
        candidate_id: "candidate-1".to_string(),
        seed: 7,
        model: "fixture".to_string(),
        temperature: 0.0,
        strategy: "fixture".to_string(),
        origin: StudioArtifactOutputOrigin::FixtureRuntime,
        provenance: None,
        summary: "Fixture candidate".to_string(),
        renderable_paths: vec!["index.html".to_string()],
        selected: true,
        fallback: false,
        failure: None,
        raw_output_preview: None,
        convergence: Some(StudioArtifactCandidateConvergenceTrace {
            lineage_root_id: "candidate-1".to_string(),
            parent_candidate_id: None,
            pass_kind: "semantic_refinement".to_string(),
            pass_index: 1,
            score_total: 412,
            score_delta_from_parent: Some(24),
            terminated_reason: None,
        }),
        render_evaluation: None,
        validation: validation.clone(),
    }
}

#[test]
fn build_artifact_lane_receipts_captures_all_conformance_categories() {
    let validation = sample_validation();
    let receipts = build_artifact_lane_receipts(
        Some(&sample_blueprint()),
        &[sample_selected_skill()],
        &[sample_candidate_summary(&validation)],
        &validation,
        StudioArtifactUxLifecycle::Validated,
    );

    let kinds = receipts
        .iter()
        .map(|receipt| receipt.kind.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        kinds,
        vec![
            "blueprint_family",
            "skill_discovery_evidence",
            "scaffold_family",
            "component_pack_inventory",
            "audit_findings",
            "validation_findings",
            "repair_passes",
            "presentation_gate",
        ]
    );
    assert_eq!(receipts[1].status, "success");
    assert_eq!(receipts[6].status, "warning");
    assert!(receipts[3]
        .details
        .iter()
        .any(|detail| detail == "tabbed_evidence_rail"));
}
