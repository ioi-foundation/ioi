use super::*;

#[test]
fn connector_grounding_is_carried_into_artifact_brief() {
    let mut brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "summarize unread mail clearly".to_string(),
        subject_domain: "email summaries".to_string(),
        artifact_thesis: "Present the inbox clearly.".to_string(),
        required_concepts: vec!["sender".to_string()],
        required_interactions: Vec::new(),
        visual_tone: vec!["editorial".to_string()],
        factual_anchors: vec!["unread email".to_string()],
        style_directives: vec!["strong hierarchy".to_string()],
        reference_hints: vec!["mail overview".to_string()],
        query_profile: None,
    };

    apply_artifact_connector_grounding_to_brief(
        &mut brief,
        Some(&ArtifactConnectorGrounding {
            connector_id: Some("mail.primary".to_string()),
            provider_family: Some("mail.wallet_network".to_string()),
            target_label: Some("email".to_string()),
        }),
    );

    assert!(brief
        .factual_anchors
        .iter()
        .any(|value| value == "selected connector data is the grounding source"));
    assert!(brief
        .reference_hints
        .iter()
        .any(|value| value == "selected connector id: mail.primary"));
    assert!(brief
        .reference_hints
        .iter()
        .any(|value| value == "selected provider family: mail.wallet_network"));
}

#[test]
fn studio_skill_query_is_structural_and_not_skill_name_routed() {
    let request = StudioOutcomeArtifactRequest {
        artifact_class: StudioArtifactClass::InteractiveSingleFile,
        deliverable_shape: StudioArtifactDeliverableShape::SingleFile,
        renderer: StudioRendererKind::HtmlIframe,
        presentation_surface: StudioPresentationSurface::SidePanel,
        persistence: StudioArtifactPersistenceMode::ArtifactScoped,
        execution_substrate: StudioExecutionSubstrate::ClientSandbox,
        workspace_recipe_id: None,
        presentation_variant_id: None,
        scope: crate::models::StudioOutcomeArtifactScope {
            target_project: None,
            create_new_workspace: false,
            mutation_boundary: vec!["artifact".to_string()],
        },
        verification: crate::models::StudioOutcomeArtifactVerificationRequest {
            require_render: true,
            require_build: false,
            require_preview: false,
            require_export: false,
            require_diff_review: false,
        },
    };
    let brief = StudioArtifactBrief {
        audience: "operators".to_string(),
        job_to_be_done: "explain the rollout clearly".to_string(),
        subject_domain: "product launch".to_string(),
        artifact_thesis: "Show adoption and satisfaction through interactive evidence.".to_string(),
        required_concepts: vec!["adoption".to_string(), "customer satisfaction".to_string()],
        required_interactions: vec![
            "view switching".to_string(),
            "detail comparison".to_string(),
        ],
        visual_tone: vec!["editorial".to_string()],
        factual_anchors: vec!["weekly adoption".to_string()],
        style_directives: vec!["structured hierarchy".to_string()],
        reference_hints: vec!["comparison cards".to_string()],
        query_profile: None,
    };
    let blueprint = derive_studio_artifact_blueprint(&request, &brief);
    let artifact_ir = compile_studio_artifact_ir(&request, &brief, &blueprint);
    let need = blueprint
        .skill_needs
        .iter()
        .find(|need| need.kind == StudioArtifactSkillNeedKind::VisualArtDirection)
        .cloned()
        .expect("visual art direction need");

    let query = build_skill_need_query(&brief, &blueprint, &artifact_ir, &need, "need-1");

    assert!(query.contains("Need kind: visual_art_direction"));
    assert!(query.contains(&format!("Scaffold family: {}", blueprint.scaffold_family)));
    assert!(query.contains("Interaction families:"));
    assert!(!query.contains("frontend-skill"));
}

#[test]
fn unrelated_lower_ranked_skill_does_not_change_primary_selection_order() {
    let primary = StudioArtifactSelectedSkill {
        skill_hash: "a".repeat(64),
        name: "layout-system".to_string(),
        description: "Primary structural layout guidance".to_string(),
        lifecycle_state: "published".to_string(),
        source_type: "skill".to_string(),
        reliability_bps: 9500,
        semantic_score_bps: 9600,
        adjusted_score_bps: 9700,
        relative_path: Some("skills/layout-system/SKILL.md".to_string()),
        matched_need_ids: vec!["visual_art_direction-1".to_string()],
        matched_need_kinds: vec![StudioArtifactSkillNeedKind::VisualArtDirection],
        match_rationale: "Best structural match.".to_string(),
        guidance_markdown: Some("Use strong hierarchy.".to_string()),
    };
    let unrelated = StudioArtifactSelectedSkill {
        skill_hash: "b".repeat(64),
        name: "spreadsheet-helper".to_string(),
        description: "Unrelated tabular helper".to_string(),
        lifecycle_state: "published".to_string(),
        source_type: "skill".to_string(),
        reliability_bps: 4200,
        semantic_score_bps: 1800,
        adjusted_score_bps: 2100,
        relative_path: Some("skills/spreadsheet-helper/SKILL.md".to_string()),
        matched_need_ids: vec!["data_story-1".to_string()],
        matched_need_kinds: vec![StudioArtifactSkillNeedKind::DataStorytelling],
        match_rationale: "Loose match.".to_string(),
        guidance_markdown: Some("Consider tabular summaries.".to_string()),
    };

    let selected =
        sort_and_truncate_selected_skills(vec![(1, 1, primary.clone()), (0, 1, unrelated)]);

    assert_eq!(
        selected.first().map(|skill| skill.name.as_str()),
        Some("layout-system")
    );
    assert_eq!(selected.len(), 2);
}
