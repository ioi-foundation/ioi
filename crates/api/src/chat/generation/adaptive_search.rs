use super::*;

pub(super) fn renderer_candidate_cap(
    renderer: ChatRendererKind,
    production_kind: ChatRuntimeProvenanceKind,
) -> usize {
    match renderer {
        ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox => {
            if production_kind == ChatRuntimeProvenanceKind::RealLocalRuntime {
                3
            } else {
                4
            }
        }
        ChatRendererKind::Svg => {
            if production_kind == ChatRuntimeProvenanceKind::RealLocalRuntime {
                2
            } else {
                3
            }
        }
        ChatRendererKind::Markdown
        | ChatRendererKind::Mermaid
        | ChatRendererKind::PdfEmbed
        | ChatRendererKind::DownloadCard
        | ChatRendererKind::BundleManifest => {
            if production_kind == ChatRuntimeProvenanceKind::RealLocalRuntime {
                1
            } else {
                2
            }
        }
        ChatRendererKind::WorkspaceSurface => 1,
    }
}

pub(super) fn renderer_shortlist_cap(renderer: ChatRendererKind) -> usize {
    match renderer {
        ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox => 3,
        ChatRendererKind::Svg => 2,
        ChatRendererKind::Markdown
        | ChatRendererKind::Mermaid
        | ChatRendererKind::PdfEmbed
        | ChatRendererKind::DownloadCard
        | ChatRendererKind::BundleManifest => 2,
        ChatRendererKind::WorkspaceSurface => 1,
    }
}

pub(super) fn renderer_refinement_cap(
    renderer: ChatRendererKind,
    production_kind: ChatRuntimeProvenanceKind,
) -> usize {
    match renderer {
        ChatRendererKind::HtmlIframe => {
            if production_kind == ChatRuntimeProvenanceKind::RealLocalRuntime {
                3
            } else {
                3
            }
        }
        ChatRendererKind::JsxSandbox | ChatRendererKind::Svg => 2,
        _ => 0,
    }
}

pub(crate) fn derive_chat_adaptive_search_budget(
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    blueprint: Option<&ChatArtifactBlueprint>,
    artifact_ir: Option<&ChatArtifactIR>,
    selected_skills: &[ChatArtifactSelectedSkill],
    retrieved_exemplars: &[ChatArtifactExemplar],
    refinement: Option<&ChatArtifactRefinementContext>,
    production_kind: ChatRuntimeProvenanceKind,
    runtime_profile: ChatArtifactRuntimePolicyProfile,
    _acceptance_distinct: bool,
) -> ChatAdaptiveSearchBudget {
    let (initial_candidate_count, _, _) =
        candidate_generation_config(request.renderer, production_kind);
    let initial_candidate_count = initial_candidate_count.max(1);
    let baseline_refinement_passes =
        semantic_refinement_pass_limit(request.renderer, production_kind);
    let mut max_candidate_count = initial_candidate_count;
    let mut shortlist_limit = 1usize;
    let mut max_semantic_refinement_passes = baseline_refinement_passes;
    let mut plateau_limit = usize::from(baseline_refinement_passes > 0);
    let min_score_delta = if baseline_refinement_passes > 0 {
        1
    } else {
        i32::MAX
    };
    let mut target_validation_score_for_early_stop = match request.renderer {
        ChatRendererKind::HtmlIframe => 356,
        ChatRendererKind::JsxSandbox => 348,
        ChatRendererKind::Svg => 340,
        ChatRendererKind::Markdown => 312,
        ChatRendererKind::Mermaid => 308,
        ChatRendererKind::PdfEmbed => 314,
        ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest => 306,
        ChatRendererKind::WorkspaceSurface => 300,
    };
    let mut expansion_score_margin = match request.renderer {
        ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox => 18,
        ChatRendererKind::Svg => 16,
        ChatRendererKind::Markdown | ChatRendererKind::Mermaid | ChatRendererKind::PdfEmbed => 14,
        ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest => 12,
        ChatRendererKind::WorkspaceSurface => 8,
    };
    let mut signals = Vec::new();

    if matches!(
        request.renderer,
        ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox | ChatRendererKind::Svg
    ) && !(request.renderer == ChatRendererKind::HtmlIframe
        && production_kind == ChatRuntimeProvenanceKind::RealLocalRuntime)
    {
        record_adaptive_search_signal(&mut signals, ChatAdaptiveSearchSignal::RendererComplexity);
        max_candidate_count += 1;
        shortlist_limit = shortlist_limit.max(2);
    }

    let interaction_load = brief
        .required_interaction_goal_count()
        .max(
            blueprint
                .map(|value| value.interaction_plan.len())
                .unwrap_or_default(),
        )
        .max(
            artifact_ir
                .map(|value| value.interaction_graph.len())
                .unwrap_or_default(),
        );
    if interaction_load >= 3 {
        record_adaptive_search_signal(&mut signals, ChatAdaptiveSearchSignal::BriefInteractionLoad);
        max_candidate_count += 1;
        shortlist_limit = shortlist_limit.max(2);
        max_semantic_refinement_passes = max_semantic_refinement_passes.saturating_add(1);
        plateau_limit = plateau_limit.max(1);
        target_validation_score_for_early_stop += 6;
        expansion_score_margin += 4;
    }

    let concept_load = brief
        .required_concepts
        .len()
        .max(
            blueprint
                .map(|value| value.evidence_plan.len())
                .unwrap_or_default(),
        )
        .max(
            artifact_ir
                .map(|value| value.evidence_surfaces.len())
                .unwrap_or_default(),
        );
    if concept_load >= 4 {
        record_adaptive_search_signal(&mut signals, ChatAdaptiveSearchSignal::BriefConceptLoad);
        max_candidate_count += 1;
        shortlist_limit = shortlist_limit.max(2);
        max_semantic_refinement_passes = max_semantic_refinement_passes.saturating_add(1);
        target_validation_score_for_early_stop += 4;
    }

    if !selected_skills.is_empty() {
        record_adaptive_search_signal(&mut signals, ChatAdaptiveSearchSignal::SkillBackedDesign);
        shortlist_limit = shortlist_limit.max(2);
        target_validation_score_for_early_stop += 4;
    }

    if !retrieved_exemplars.is_empty() {
        record_adaptive_search_signal(&mut signals, ChatAdaptiveSearchSignal::ExemplarSupport);
        shortlist_limit = shortlist_limit.max(2);
        expansion_score_margin = (expansion_score_margin - 2).max(10);
    }

    if refinement.is_some() {
        record_adaptive_search_signal(&mut signals, ChatAdaptiveSearchSignal::ContinuationEdit);
        max_candidate_count = max_candidate_count.min(initial_candidate_count.saturating_add(1));
        shortlist_limit = 1;
        target_validation_score_for_early_stop += 4;
    }

    if production_kind == ChatRuntimeProvenanceKind::RealLocalRuntime {
        record_adaptive_search_signal(
            &mut signals,
            ChatAdaptiveSearchSignal::LocalGenerationConstraint,
        );
        max_candidate_count = max_candidate_count.min(initial_candidate_count.saturating_add(1));
    }

    if production_kind == ChatRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == ChatRendererKind::HtmlIframe
        && chat_modal_first_html_enabled()
    {
        let validation_backed_modal_html_lane = matches!(
            runtime_profile,
            ChatArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                | ChatArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
                | ChatArtifactRuntimePolicyProfile::PremiumEndToEnd
        );
        if validation_backed_modal_html_lane {
            max_candidate_count =
                max_candidate_count.max(initial_candidate_count.saturating_add(2));
            shortlist_limit = shortlist_limit.max(3);
            max_semantic_refinement_passes = max_semantic_refinement_passes.max(3);
            plateau_limit = plateau_limit.max(2);
        } else {
            max_candidate_count = initial_candidate_count;
            shortlist_limit = 1;
            max_semantic_refinement_passes = max_semantic_refinement_passes.min(1);
        }
    }

    max_candidate_count = max_candidate_count.clamp(
        initial_candidate_count,
        renderer_candidate_cap(request.renderer, production_kind),
    );
    shortlist_limit = shortlist_limit
        .max(1)
        .min(renderer_shortlist_cap(request.renderer))
        .min(max_candidate_count);
    max_semantic_refinement_passes = max_semantic_refinement_passes
        .min(renderer_refinement_cap(request.renderer, production_kind));
    let plateau_limit = if max_semantic_refinement_passes > 0 {
        plateau_limit.max(1).min(2)
    } else {
        0
    };

    ChatAdaptiveSearchBudget {
        initial_candidate_count,
        max_candidate_count,
        shortlist_limit,
        max_semantic_refinement_passes,
        plateau_limit,
        min_score_delta,
        target_validation_score_for_early_stop,
        expansion_score_margin,
        signals,
    }
}

pub(crate) fn ranked_candidate_indices_by_score(
    candidate_summaries: &[ChatArtifactCandidateSummary],
) -> Vec<usize> {
    let mut ranked = candidate_summaries
        .iter()
        .enumerate()
        .map(|(index, summary)| (index, validation_total_score(&summary.validation)))
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    ranked.into_iter().map(|(index, _)| index).collect()
}

pub(super) fn top_candidate_score_gap(
    ranked_candidate_indices: &[usize],
    candidate_summaries: &[ChatArtifactCandidateSummary],
) -> Option<i32> {
    let best_index = ranked_candidate_indices.first().copied()?;
    let best_score = validation_total_score(&candidate_summaries.get(best_index)?.validation);
    let second_score = ranked_candidate_indices
        .get(1)
        .and_then(|index| candidate_summaries.get(*index))
        .map(|summary| validation_total_score(&summary.validation))
        .unwrap_or(best_score);
    Some((best_score - second_score).max(0))
}

pub(crate) fn target_candidate_count_after_initial_search(
    adaptive_budget: &mut ChatAdaptiveSearchBudget,
    ranked_candidate_indices: &[usize],
    candidate_summaries: &[ChatArtifactCandidateSummary],
    failed_candidate_count: usize,
) -> usize {
    let current_count = candidate_summaries
        .len()
        .max(adaptive_budget.initial_candidate_count);
    if current_count >= adaptive_budget.max_candidate_count {
        return current_count;
    }

    let Some(best_index) = ranked_candidate_indices.first().copied() else {
        return adaptive_budget.max_candidate_count;
    };
    let best_score = candidate_summaries
        .get(best_index)
        .map(|summary| validation_total_score(&summary.validation))
        .unwrap_or_default();
    let score_gap =
        top_candidate_score_gap(ranked_candidate_indices, candidate_summaries).unwrap_or_default();
    if score_gap <= adaptive_budget.expansion_score_margin {
        record_adaptive_search_signal(
            &mut adaptive_budget.signals,
            ChatAdaptiveSearchSignal::LowCandidateVariance,
        );
    } else {
        record_adaptive_search_signal(
            &mut adaptive_budget.signals,
            ChatAdaptiveSearchSignal::HighCandidateVariance,
        );
    }

    let clears_primary_view = ranked_candidate_indices.iter().copied().any(|index| {
        candidate_summaries
            .get(index)
            .map(|summary| validation_clears_primary_view(&summary.validation))
            .unwrap_or(false)
    });
    if !clears_primary_view {
        record_adaptive_search_signal(
            &mut adaptive_budget.signals,
            ChatAdaptiveSearchSignal::NoPrimaryViewCandidate,
        );
    }
    if !clears_primary_view
        && best_score + adaptive_budget.expansion_score_margin
            >= adaptive_budget.target_validation_score_for_early_stop
    {
        record_adaptive_search_signal(
            &mut adaptive_budget.signals,
            ChatAdaptiveSearchSignal::NearMissPrimaryView,
        );
    }
    if failed_candidate_count > 0 {
        record_adaptive_search_signal(
            &mut adaptive_budget.signals,
            ChatAdaptiveSearchSignal::GenerationFailureObserved,
        );
    }

    let should_expand = !clears_primary_view
        && (failed_candidate_count > 0
            || best_score < adaptive_budget.target_validation_score_for_early_stop
            || score_gap <= adaptive_budget.expansion_score_margin);
    if should_expand {
        adaptive_budget.max_candidate_count
    } else {
        current_count
    }
}

pub(crate) fn shortlisted_candidate_indices_for_budget(
    adaptive_budget: &mut ChatAdaptiveSearchBudget,
    ranked_candidate_indices: &[usize],
    candidate_summaries: &[ChatArtifactCandidateSummary],
) -> Vec<usize> {
    if ranked_candidate_indices.is_empty() {
        return Vec::new();
    }

    if let Some(score_gap) = top_candidate_score_gap(ranked_candidate_indices, candidate_summaries)
    {
        if score_gap <= adaptive_budget.expansion_score_margin {
            record_adaptive_search_signal(
                &mut adaptive_budget.signals,
                ChatAdaptiveSearchSignal::LowCandidateVariance,
            );
            adaptive_budget.shortlist_limit = adaptive_budget.shortlist_limit.max(2);
        } else {
            record_adaptive_search_signal(
                &mut adaptive_budget.signals,
                ChatAdaptiveSearchSignal::HighCandidateVariance,
            );
        }
    }

    adaptive_budget.shortlist_limit = adaptive_budget
        .shortlist_limit
        .max(1)
        .min(ranked_candidate_indices.len())
        .min(adaptive_budget.max_candidate_count);

    let mut shortlisted = ranked_candidate_indices
        .iter()
        .copied()
        .filter(|index| {
            candidate_summaries
                .get(*index)
                .map(|summary| validation_clears_primary_view(&summary.validation))
                .unwrap_or(false)
        })
        .take(adaptive_budget.shortlist_limit)
        .collect::<Vec<_>>();
    if shortlisted.is_empty() {
        shortlisted = ranked_candidate_indices
            .iter()
            .take(adaptive_budget.shortlist_limit)
            .copied()
            .collect();
    }
    shortlisted
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn requested_follow_up_pass(
    validation: &ChatArtifactValidationResult,
) -> Option<&'static str> {
    if validation.classification == ChatArtifactValidationStatus::Repairable {
        let render_warning_only = validation
            .issue_classes
            .iter()
            .any(|value| value == "render_eval")
            && validation.blocked_reasons.is_empty()
            && !validation.generic_shell_detected
            && !validation.trivial_shell_detected;
        if validation.recommended_next_pass.as_deref() == Some("polish_pass") && render_warning_only
        {
            return Some("polish_pass");
        }
        if validation.recommended_next_pass.as_deref() == Some("accept") && render_warning_only {
            return Some("polish_pass");
        }
        return Some("structural_repair");
    }
    if validation.classification == ChatArtifactValidationStatus::Blocked {
        let recommended = validation.recommended_next_pass.as_deref();
        let recoverable = !validation.trivial_shell_detected
            && (matches!(recommended, Some("structural_repair") | Some("polish_pass"))
                || !validation.repair_hints.is_empty());
        if recoverable {
            return match recommended {
                Some("polish_pass") => Some("polish_pass"),
                _ => Some("structural_repair"),
            };
        }
    }
    if validation.classification == ChatArtifactValidationStatus::Pass
        && !validation_clears_primary_view(validation)
        && (validation.visual_hierarchy < 5 || validation.layout_coherence < 5)
    {
        return Some("polish_pass");
    }

    match validation.recommended_next_pass.as_deref() {
        Some("structural_repair") => Some("structural_repair"),
        Some("polish_pass") => Some("polish_pass"),
        Some("accept") | Some("hold_block") => None,
        _ => match validation.classification {
            _ => None,
        },
    }
}

pub(super) fn initial_candidate_convergence_trace(
    candidate_id: &str,
    pass_kind: &str,
    score_total: i32,
) -> ChatArtifactCandidateConvergenceTrace {
    ChatArtifactCandidateConvergenceTrace {
        lineage_root_id: refined_candidate_root(candidate_id).to_string(),
        parent_candidate_id: None,
        pass_kind: pass_kind.to_string(),
        pass_index: 0,
        score_total,
        score_delta_from_parent: None,
        terminated_reason: None,
    }
}

pub(super) fn set_candidate_termination_reason(
    summary: &mut ChatArtifactCandidateSummary,
    reason: impl Into<String>,
) {
    if let Some(convergence) = summary.convergence.as_mut() {
        convergence.terminated_reason = Some(reason.into());
    }
}
