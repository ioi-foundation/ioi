use super::brief::{
    brief_interaction_families, brief_interaction_goals, brief_required_interaction_summaries,
    interaction_family_for_kind, normalize_inline_whitespace,
};
use crate::studio::*;
use ioi_types::app::{StudioOutcomeArtifactRequest, StudioRendererKind};

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

fn blueprint_scaffold_family(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
) -> String {
    match request.renderer {
        StudioRendererKind::HtmlIframe => {
            let families = brief_interaction_families(brief);
            if families.contains(&"sequence_browsing") {
                "guided_tutorial".to_string()
            } else if families.contains(&"view_switching") {
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

    let interaction_families = brief_interaction_families(brief);

    if interaction_families.contains(&"sequence_browsing") {
        skill_needs.push(StudioArtifactSkillNeed {
            kind: StudioArtifactSkillNeedKind::MotionHierarchy,
            priority: StudioArtifactSkillNeedPriority::Recommended,
            rationale:
                "Sequence browsing benefits from restrained choreography and progression cues."
                    .to_string(),
        });
    }

    if interaction_families.contains(&"view_switching")
        || interaction_families.contains(&"detail_inspection")
    {
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
    if matches!(
        request.renderer,
        StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed
    ) {
        return vec![
            StudioArtifactSectionPlan {
                id: "document-summary".to_string(),
                role: "document_summary".to_string(),
                visible_purpose: "Open with a clear title and compact summary.".to_string(),
                content_requirements: vec![
                    brief.artifact_thesis.clone(),
                    brief.job_to_be_done.clone(),
                ],
                interaction_hooks: Vec::new(),
                first_paint_requirements: vec![
                    "Show the title and summary immediately on first paint.".to_string(),
                ],
            },
            StudioArtifactSectionPlan {
                id: "key-points".to_string(),
                role: "key_points".to_string(),
                visible_purpose: "Make the request-grounded concepts easy to scan.".to_string(),
                content_requirements: concept_requirements,
                interaction_hooks: Vec::new(),
                first_paint_requirements: vec![
                    "Render clearly segmented bullets, headings, or subsections instead of one uninterrupted paragraph."
                        .to_string(),
                ],
            },
            StudioArtifactSectionPlan {
                id: "supporting-evidence".to_string(),
                role: "supporting_evidence".to_string(),
                visible_purpose: "Back the summary with grounded evidence or examples.".to_string(),
                content_requirements: evidence_requirements,
                interaction_hooks: Vec::new(),
                first_paint_requirements: vec![
                    "Surface labeled evidence, examples, or explanatory notes inside the document body."
                        .to_string(),
                ],
            },
            StudioArtifactSectionPlan {
                id: "closing".to_string(),
                role: "closing".to_string(),
                visible_purpose: "End with a takeaway or next-step framing.".to_string(),
                content_requirements: vec![
                    "Summarize the core takeaway clearly.".to_string(),
                    "Close with a concrete implication, risk, or next step.".to_string(),
                ],
                interaction_hooks: Vec::new(),
                first_paint_requirements: vec![
                    "End with a visible closing section rather than an abrupt stop.".to_string(),
                ],
            },
        ];
    }
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
        let interaction_summaries = brief_required_interaction_summaries(brief);
        sections.push(StudioArtifactSectionPlan {
            id: "interaction-lab".to_string(),
            role: "interaction_lab".to_string(),
            visible_purpose: "Make the planned interaction families tangible.".to_string(),
            content_requirements: concise_requirement_list(
                &interaction_summaries,
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

fn blueprint_interaction_plan(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
) -> Vec<StudioArtifactInteractionPlan> {
    if matches!(
        request.renderer,
        StudioRendererKind::Markdown
            | StudioRendererKind::PdfEmbed
            | StudioRendererKind::Svg
            | StudioRendererKind::Mermaid
            | StudioRendererKind::DownloadCard
            | StudioRendererKind::BundleManifest
    ) {
        return Vec::new();
    }

    let interaction_goals = brief_interaction_goals(brief);
    let mut plans = interaction_goals
        .iter()
        .enumerate()
        .map(|(index, interaction)| {
            let family = interaction_family_for_kind(interaction.kind).to_string();
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
                                "Visible explanatory context is rendered before interaction."
                                    .to_string()
                            } else {
                                "Visible detail text is rendered before interaction.".to_string()
                            },
                            "Focusable marks or buttons already exist on first paint.".to_string(),
                        ],
                    ),
                    "sequence_browsing" => (
                        vec!["stepper".to_string(), "previous_next_controls".to_string()],
                        if studio_modal_first_html_enabled() {
                            vec![
                                "sequence_surface".to_string(),
                                "inline_annotation_surface".to_string(),
                            ]
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

fn blueprint_evidence_plan(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
) -> Vec<StudioArtifactEvidencePlanEntry> {
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
    if matches!(
        request.renderer,
        StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed
    ) {
        return vec![
            StudioArtifactEvidencePlanEntry {
                id: "document-support".to_string(),
                kind: "supporting_surface".to_string(),
                purpose:
                    "Ground the document with labeled examples, evidence, or explicit takeaways."
                        .to_string(),
                concept_bindings: seed_concepts.clone(),
                first_paint_elements: vec![
                    "section headings".to_string(),
                    "bulleted or segmented supporting points".to_string(),
                ],
                detail_targets: seed_evidence.clone(),
            },
            StudioArtifactEvidencePlanEntry {
                id: "closing-signal".to_string(),
                kind: "summary_surface".to_string(),
                purpose: "Leave the document with a clearly surfaced concluding signal."
                    .to_string(),
                concept_bindings: seed_concepts,
                first_paint_elements: vec![
                    "closing takeaway".to_string(),
                    "explicit implication or next step".to_string(),
                ],
                detail_targets: seed_evidence,
            },
        ];
    }

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
    if matches!(
        blueprint.renderer,
        StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed
    ) {
        push_component(
            &mut plan,
            "document_section_stack",
            "document_structure",
            &[
                "document-summary",
                "key-points",
                "supporting-evidence",
                "closing",
            ],
            Vec::new(),
        );
        push_component(
            &mut plan,
            "bullet_list",
            "scannable_points",
            &["key-points", "supporting-evidence"],
            Vec::new(),
        );
        push_component(
            &mut plan,
            "callout_block",
            "summary_takeaway",
            &["document-summary", "closing"],
            Vec::new(),
        );
        return plan;
    }
    push_component(
        &mut plan,
        "hero_frame",
        "orientation",
        &["hero"],
        Vec::new(),
    );
    if matches!(
        blueprint.renderer,
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
    ) && !studio_modal_first_html_enabled()
    {
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
    if matches!(
        blueprint.renderer,
        StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed
    ) {
        return StudioArtifactAccessibilityPlan {
            obligations: vec![
                "Use semantic headings and preserve a readable document outline.".to_string(),
                "Keep bullets, tables, and callouts legible without relying on interaction."
                    .to_string(),
            ],
            focus_order: blueprint
                .section_plan
                .iter()
                .map(|section| section.id.clone())
                .collect(),
            aria_expectations: vec![
                "Document headings remain structurally ordered.".to_string(),
                "Lists and supporting callouts stay readable in export and preview.".to_string(),
            ],
        };
    }

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
        minimum_section_count: if matches!(
            request.renderer,
            StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed
        ) {
            1
        } else {
            blueprint.section_plan.len().min(u8::MAX as usize) as u8
        },
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
    let interaction_plan = blueprint_interaction_plan(request, brief);
    let evidence_plan = blueprint_evidence_plan(request, brief);
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
