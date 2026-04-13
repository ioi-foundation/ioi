use super::*;

pub(super) fn renderer_candidate_cap(
    renderer: StudioRendererKind,
    production_kind: StudioRuntimeProvenanceKind,
) -> usize {
    match renderer {
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => {
            if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                3
            } else {
                4
            }
        }
        StudioRendererKind::Svg => {
            if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                2
            } else {
                3
            }
        }
        StudioRendererKind::Markdown
        | StudioRendererKind::Mermaid
        | StudioRendererKind::PdfEmbed
        | StudioRendererKind::DownloadCard
        | StudioRendererKind::BundleManifest => {
            if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                1
            } else {
                2
            }
        }
        StudioRendererKind::WorkspaceSurface => 1,
    }
}

pub(super) fn renderer_shortlist_cap(renderer: StudioRendererKind) -> usize {
    match renderer {
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => 3,
        StudioRendererKind::Svg => 2,
        StudioRendererKind::Markdown
        | StudioRendererKind::Mermaid
        | StudioRendererKind::PdfEmbed
        | StudioRendererKind::DownloadCard
        | StudioRendererKind::BundleManifest => 2,
        StudioRendererKind::WorkspaceSurface => 1,
    }
}

pub(super) fn renderer_refinement_cap(
    renderer: StudioRendererKind,
    production_kind: StudioRuntimeProvenanceKind,
) -> usize {
    match renderer {
        StudioRendererKind::HtmlIframe => {
            if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                3
            } else {
                3
            }
        }
        StudioRendererKind::JsxSandbox | StudioRendererKind::Svg => 2,
        _ => 0,
    }
}

pub(crate) fn derive_studio_adaptive_search_budget(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    refinement: Option<&StudioArtifactRefinementContext>,
    production_kind: StudioRuntimeProvenanceKind,
    runtime_profile: StudioArtifactRuntimePolicyProfile,
    _acceptance_distinct: bool,
) -> StudioAdaptiveSearchBudget {
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
    let mut target_judge_score_for_early_stop = match request.renderer {
        StudioRendererKind::HtmlIframe => 356,
        StudioRendererKind::JsxSandbox => 348,
        StudioRendererKind::Svg => 340,
        StudioRendererKind::Markdown => 312,
        StudioRendererKind::Mermaid => 308,
        StudioRendererKind::PdfEmbed => 314,
        StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest => 306,
        StudioRendererKind::WorkspaceSurface => 300,
    };
    let mut expansion_score_margin = match request.renderer {
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => 18,
        StudioRendererKind::Svg => 16,
        StudioRendererKind::Markdown
        | StudioRendererKind::Mermaid
        | StudioRendererKind::PdfEmbed => 14,
        StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest => 12,
        StudioRendererKind::WorkspaceSurface => 8,
    };
    let mut signals = Vec::new();

    if matches!(
        request.renderer,
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox | StudioRendererKind::Svg
    ) && !(request.renderer == StudioRendererKind::HtmlIframe
        && production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime)
    {
        record_adaptive_search_signal(&mut signals, StudioAdaptiveSearchSignal::RendererComplexity);
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
        record_adaptive_search_signal(
            &mut signals,
            StudioAdaptiveSearchSignal::BriefInteractionLoad,
        );
        max_candidate_count += 1;
        shortlist_limit = shortlist_limit.max(2);
        max_semantic_refinement_passes = max_semantic_refinement_passes.saturating_add(1);
        plateau_limit = plateau_limit.max(1);
        target_judge_score_for_early_stop += 6;
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
        record_adaptive_search_signal(&mut signals, StudioAdaptiveSearchSignal::BriefConceptLoad);
        max_candidate_count += 1;
        shortlist_limit = shortlist_limit.max(2);
        max_semantic_refinement_passes = max_semantic_refinement_passes.saturating_add(1);
        target_judge_score_for_early_stop += 4;
    }

    if !selected_skills.is_empty() {
        record_adaptive_search_signal(&mut signals, StudioAdaptiveSearchSignal::SkillBackedDesign);
        shortlist_limit = shortlist_limit.max(2);
        target_judge_score_for_early_stop += 4;
    }

    if !retrieved_exemplars.is_empty() {
        record_adaptive_search_signal(&mut signals, StudioAdaptiveSearchSignal::ExemplarSupport);
        shortlist_limit = shortlist_limit.max(2);
        expansion_score_margin = (expansion_score_margin - 2).max(10);
    }

    if refinement.is_some() {
        record_adaptive_search_signal(&mut signals, StudioAdaptiveSearchSignal::ContinuationEdit);
        max_candidate_count = max_candidate_count.min(initial_candidate_count.saturating_add(1));
        shortlist_limit = 1;
        target_judge_score_for_early_stop += 4;
    }

    if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
        record_adaptive_search_signal(
            &mut signals,
            StudioAdaptiveSearchSignal::LocalGenerationConstraint,
        );
        max_candidate_count = max_candidate_count.min(initial_candidate_count.saturating_add(1));
    }

    if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == StudioRendererKind::HtmlIframe
        && studio_modal_first_html_enabled()
    {
        let judge_backed_modal_html_lane = matches!(
            runtime_profile,
            StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                | StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
                | StudioArtifactRuntimePolicyProfile::PremiumEndToEnd
        );
        if judge_backed_modal_html_lane {
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

    StudioAdaptiveSearchBudget {
        initial_candidate_count,
        max_candidate_count,
        shortlist_limit,
        max_semantic_refinement_passes,
        plateau_limit,
        min_score_delta,
        target_judge_score_for_early_stop,
        expansion_score_margin,
        signals,
    }
}

pub(crate) fn ranked_candidate_indices_by_score(
    candidate_summaries: &[StudioArtifactCandidateSummary],
) -> Vec<usize> {
    let mut ranked = candidate_summaries
        .iter()
        .enumerate()
        .map(|(index, summary)| (index, judge_total_score(&summary.judge)))
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| right.1.cmp(&left.1).then(left.0.cmp(&right.0)));
    ranked.into_iter().map(|(index, _)| index).collect()
}

pub(super) fn top_candidate_score_gap(
    ranked_candidate_indices: &[usize],
    candidate_summaries: &[StudioArtifactCandidateSummary],
) -> Option<i32> {
    let best_index = ranked_candidate_indices.first().copied()?;
    let best_score = judge_total_score(&candidate_summaries.get(best_index)?.judge);
    let second_score = ranked_candidate_indices
        .get(1)
        .and_then(|index| candidate_summaries.get(*index))
        .map(|summary| judge_total_score(&summary.judge))
        .unwrap_or(best_score);
    Some((best_score - second_score).max(0))
}

pub(crate) fn target_candidate_count_after_initial_search(
    adaptive_budget: &mut StudioAdaptiveSearchBudget,
    ranked_candidate_indices: &[usize],
    candidate_summaries: &[StudioArtifactCandidateSummary],
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
        .map(|summary| judge_total_score(&summary.judge))
        .unwrap_or_default();
    let score_gap =
        top_candidate_score_gap(ranked_candidate_indices, candidate_summaries).unwrap_or_default();
    if score_gap <= adaptive_budget.expansion_score_margin {
        record_adaptive_search_signal(
            &mut adaptive_budget.signals,
            StudioAdaptiveSearchSignal::LowCandidateVariance,
        );
    } else {
        record_adaptive_search_signal(
            &mut adaptive_budget.signals,
            StudioAdaptiveSearchSignal::HighCandidateVariance,
        );
    }

    let clears_primary_view = ranked_candidate_indices.iter().copied().any(|index| {
        candidate_summaries
            .get(index)
            .map(|summary| judge_clears_primary_view(&summary.judge))
            .unwrap_or(false)
    });
    if !clears_primary_view {
        record_adaptive_search_signal(
            &mut adaptive_budget.signals,
            StudioAdaptiveSearchSignal::NoPrimaryViewCandidate,
        );
    }
    if !clears_primary_view
        && best_score + adaptive_budget.expansion_score_margin
            >= adaptive_budget.target_judge_score_for_early_stop
    {
        record_adaptive_search_signal(
            &mut adaptive_budget.signals,
            StudioAdaptiveSearchSignal::NearMissPrimaryView,
        );
    }
    if failed_candidate_count > 0 {
        record_adaptive_search_signal(
            &mut adaptive_budget.signals,
            StudioAdaptiveSearchSignal::GenerationFailureObserved,
        );
    }

    let should_expand = !clears_primary_view
        && (failed_candidate_count > 0
            || best_score < adaptive_budget.target_judge_score_for_early_stop
            || score_gap <= adaptive_budget.expansion_score_margin);
    if should_expand {
        adaptive_budget.max_candidate_count
    } else {
        current_count
    }
}

pub(crate) fn shortlisted_candidate_indices_for_budget(
    adaptive_budget: &mut StudioAdaptiveSearchBudget,
    ranked_candidate_indices: &[usize],
    candidate_summaries: &[StudioArtifactCandidateSummary],
) -> Vec<usize> {
    if ranked_candidate_indices.is_empty() {
        return Vec::new();
    }

    if let Some(score_gap) = top_candidate_score_gap(ranked_candidate_indices, candidate_summaries)
    {
        if score_gap <= adaptive_budget.expansion_score_margin {
            record_adaptive_search_signal(
                &mut adaptive_budget.signals,
                StudioAdaptiveSearchSignal::LowCandidateVariance,
            );
            adaptive_budget.shortlist_limit = adaptive_budget.shortlist_limit.max(2);
        } else {
            record_adaptive_search_signal(
                &mut adaptive_budget.signals,
                StudioAdaptiveSearchSignal::HighCandidateVariance,
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
                .map(|summary| judge_clears_primary_view(&summary.judge))
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
pub(crate) fn requested_follow_up_pass(judge: &StudioArtifactJudgeResult) -> Option<&'static str> {
    if judge.classification == StudioArtifactJudgeClassification::Repairable {
        let render_warning_only = judge
            .issue_classes
            .iter()
            .any(|value| value == "render_eval")
            && judge.blocked_reasons.is_empty()
            && !judge.generic_shell_detected
            && !judge.trivial_shell_detected;
        if judge.recommended_next_pass.as_deref() == Some("polish_pass") && render_warning_only {
            return Some("polish_pass");
        }
        if judge.recommended_next_pass.as_deref() == Some("accept") && render_warning_only {
            return Some("polish_pass");
        }
        return Some("structural_repair");
    }
    if judge.classification == StudioArtifactJudgeClassification::Blocked {
        let recommended = judge.recommended_next_pass.as_deref();
        let recoverable = !judge.trivial_shell_detected
            && (matches!(recommended, Some("structural_repair") | Some("polish_pass"))
                || !judge.repair_hints.is_empty());
        if recoverable {
            return match recommended {
                Some("polish_pass") => Some("polish_pass"),
                _ => Some("structural_repair"),
            };
        }
    }
    if judge.classification == StudioArtifactJudgeClassification::Pass
        && !judge_clears_primary_view(judge)
        && (judge.visual_hierarchy < 5 || judge.layout_coherence < 5)
    {
        return Some("polish_pass");
    }

    match judge.recommended_next_pass.as_deref() {
        Some("structural_repair") => Some("structural_repair"),
        Some("polish_pass") => Some("polish_pass"),
        Some("accept") | Some("hold_block") => None,
        _ => match judge.classification {
            _ => None,
        },
    }
}

pub(super) fn initial_candidate_convergence_trace(
    candidate_id: &str,
    pass_kind: &str,
    score_total: i32,
) -> StudioArtifactCandidateConvergenceTrace {
    StudioArtifactCandidateConvergenceTrace {
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
    summary: &mut StudioArtifactCandidateSummary,
    reason: impl Into<String>,
) {
    if let Some(convergence) = summary.convergence.as_mut() {
        convergence.terminated_reason = Some(reason.into());
    }
}
