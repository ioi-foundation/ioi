use super::*;
use async_trait::async_trait;

#[async_trait]
pub trait StudioArtifactRenderEvaluator: Send + Sync {
    async fn evaluate_candidate_render(
        &self,
        request: &StudioOutcomeArtifactRequest,
        brief: &StudioArtifactBrief,
        blueprint: Option<&StudioArtifactBlueprint>,
        artifact_ir: Option<&StudioArtifactIR>,
        edit_intent: Option<&StudioArtifactEditIntent>,
        candidate: &StudioGeneratedArtifactPayload,
    ) -> Result<Option<StudioArtifactRenderEvaluation>, String>;
}

pub async fn evaluate_studio_artifact_render_if_configured(
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    edit_intent: Option<&StudioArtifactEditIntent>,
    candidate: &StudioGeneratedArtifactPayload,
) -> Result<Option<StudioArtifactRenderEvaluation>, String> {
    match render_evaluator {
        Some(evaluator) => {
            evaluator
                .evaluate_candidate_render(
                    request,
                    brief,
                    blueprint,
                    artifact_ir,
                    edit_intent,
                    candidate,
                )
                .await
        }
        None => Ok(None),
    }
}

pub fn build_studio_artifact_render_acceptance_policy(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
) -> StudioArtifactRenderAcceptancePolicy {
    let required_interaction_goals = brief.required_interaction_goal_count();
    let require_response_region = brief.requires_response_region();
    let minimum_semantic_regions = match request.renderer {
        StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed => blueprint
            .map(|blueprint| blueprint.acceptance_targets.minimum_section_count as usize)
            .unwrap_or(1)
            .max(1),
        _ => blueprint
            .map(|blueprint| blueprint.acceptance_targets.minimum_section_count as usize)
            .unwrap_or(3)
            .max(2),
    };
    let evidence_surfaces_from_ir = artifact_ir
        .map(|artifact_ir| artifact_ir.evidence_surfaces.len())
        .unwrap_or_default();
    let minimum_evidence_surfaces = match request.renderer {
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => {
            if required_interaction_goals >= 2 || evidence_surfaces_from_ir >= 2 {
                2
            } else {
                1
            }
        }
        StudioRendererKind::Svg | StudioRendererKind::Mermaid => 1,
        _ => 0,
    };
    let minimum_actionable_affordances = match request.renderer {
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => {
            if required_interaction_goals > 0 {
                2
            } else {
                0
            }
        }
        _ => 0,
    };
    let minimum_first_paint_text_chars = match request.renderer {
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox => 60,
        StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed => 80,
        StudioRendererKind::Svg | StudioRendererKind::Mermaid => 24,
        _ => 0,
    };

    StudioArtifactRenderAcceptancePolicy {
        mode: StudioArtifactRenderPolicyMode::Balanced,
        minimum_first_paint_text_chars,
        minimum_semantic_regions,
        minimum_evidence_surfaces,
        minimum_actionable_affordances,
        blocked_score_threshold: 9,
        primary_view_score_threshold: match request.renderer {
            StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed => 15,
            _ => 18,
        },
        require_primary_region: matches!(
            request.renderer,
            StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
        ),
        require_response_region_when_interactive: require_response_region,
        require_state_change_when_interactive: required_interaction_goals > 0,
    }
}

pub fn merge_studio_artifact_render_evaluation_into_judge(
    request: &StudioOutcomeArtifactRequest,
    mut judge: StudioArtifactJudgeResult,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
) -> StudioArtifactJudgeResult {
    let Some(render_evaluation) = render_evaluation else {
        return judge;
    };
    if !render_evaluation.supported {
        return judge;
    }

    let layout_signal = average_u8(
        render_evaluation.layout_density_score,
        render_evaluation.spacing_alignment_score,
    );
    let hierarchy_signal = average_u8(
        render_evaluation.typography_contrast_score,
        render_evaluation.visual_hierarchy_score,
    );
    let completeness_signal = average_u8(
        render_evaluation.blueprint_consistency_score,
        render_evaluation.layout_density_score,
    );

    judge.layout_coherence = merge_visual_score(judge.layout_coherence, layout_signal);
    judge.visual_hierarchy = merge_visual_score(judge.visual_hierarchy, hierarchy_signal);
    judge.completeness = merge_visual_score(judge.completeness, completeness_signal);

    let blocked_render_finding = render_evaluation.findings.iter().find(|finding| {
        finding.severity == StudioArtifactRenderFindingSeverity::Blocked
            && !render_blocking_finding_is_advisory_for_request(request, finding)
    });
    let warning_count = render_evaluation
        .findings
        .iter()
        .filter(|finding| {
            finding.severity == StudioArtifactRenderFindingSeverity::Warning
                || render_blocking_finding_is_advisory_for_request(request, finding)
        })
        .count();
    let failed_required_obligation =
        render_evaluation
            .acceptance_obligations
            .iter()
            .find(|obligation| {
                obligation.required
                    && matches!(
                        obligation.status,
                        StudioArtifactAcceptanceObligationStatus::Failed
                            | StudioArtifactAcceptanceObligationStatus::Blocked
                    )
            });
    let render_clears_primary_view = render_evaluation.first_paint_captured
        && blocked_render_finding.is_none()
        && !render_evaluation.has_failed_required_obligations()
        && render_evaluation.overall_score >= render_evaluation.primary_view_score_threshold();

    if !render_clears_primary_view {
        judge.deserves_primary_artifact_view = false;
    }

    if let Some(failed_obligation) = failed_required_obligation {
        judge.classification =
            if render_evaluation.overall_score <= render_evaluation.blocked_score_threshold() {
                StudioArtifactJudgeClassification::Blocked
            } else {
                StudioArtifactJudgeClassification::Repairable
            };
        judge.deserves_primary_artifact_view = false;
        judge.recommended_next_pass = Some("structural_repair".to_string());
        let contradiction = failed_obligation
            .detail
            .as_ref()
            .map(|detail| format!("{} {}", failed_obligation.summary, detail))
            .unwrap_or_else(|| failed_obligation.summary.clone());
        judge.strongest_contradiction = Some(contradiction.clone());
        if !judge
            .issue_classes
            .iter()
            .any(|value| value == "execution_witness")
        {
            judge.issue_classes.push("execution_witness".to_string());
        }
        if !judge
            .blocked_reasons
            .iter()
            .any(|value| value == &contradiction)
        {
            judge.blocked_reasons.push(contradiction.clone());
        }
        if !judge
            .truthfulness_warnings
            .iter()
            .any(|value| value == &contradiction)
        {
            judge.truthfulness_warnings.push(contradiction.clone());
        }
        for witness in render_evaluation
            .execution_witnesses
            .iter()
            .filter(|witness| {
                matches!(
                    witness.status,
                    StudioArtifactExecutionWitnessStatus::Failed
                        | StudioArtifactExecutionWitnessStatus::Blocked
                )
            })
            .take(3)
        {
            if !judge
                .repair_hints
                .iter()
                .any(|value| value == &witness.summary)
            {
                judge.repair_hints.push(witness.summary.clone());
            }
        }
        if !judge
            .file_findings
            .iter()
            .any(|value| value.contains("required obligations"))
        {
            judge.file_findings.push(format!(
                "{}: {} failed required obligation(s) after execution-witness validation",
                candidate_renderable_path(request),
                render_evaluation.failed_required_obligation_count()
            ));
        }
    } else if let Some(blocked) = blocked_render_finding {
        judge.classification =
            if render_evaluation.overall_score <= render_evaluation.blocked_score_threshold() {
                StudioArtifactJudgeClassification::Blocked
            } else {
                StudioArtifactJudgeClassification::Repairable
            };
        judge.deserves_primary_artifact_view = false;
        judge.recommended_next_pass = Some("structural_repair".to_string());
        judge.strongest_contradiction = Some(blocked.summary.clone());
        if !judge
            .issue_classes
            .iter()
            .any(|value| value == "render_eval")
        {
            judge.issue_classes.push("render_eval".to_string());
        }
        if !judge
            .blocked_reasons
            .iter()
            .any(|value| value == &blocked.summary)
        {
            judge.blocked_reasons.push(blocked.summary.clone());
        }
        if !judge
            .truthfulness_warnings
            .iter()
            .any(|value| value == &blocked.summary)
        {
            judge.truthfulness_warnings.push(blocked.summary.clone());
        }
        if !judge
            .file_findings
            .iter()
            .any(|value| value.contains("render evaluation"))
        {
            judge.file_findings.push(format!(
                "{}: render evaluation blocked primary presentation",
                candidate_renderable_path(request)
            ));
        }
    } else if warning_count > 0
        || render_evaluation.overall_score < render_evaluation.primary_view_score_threshold()
    {
        if judge.classification == StudioArtifactJudgeClassification::Pass {
            judge.classification = StudioArtifactJudgeClassification::Repairable;
        }
        judge.deserves_primary_artifact_view &=
            render_evaluation.overall_score >= render_evaluation.primary_view_score_threshold();
        if !judge
            .issue_classes
            .iter()
            .any(|value| value == "render_eval")
        {
            judge.issue_classes.push("render_eval".to_string());
        }
        if judge.recommended_next_pass.is_none()
            || judge.recommended_next_pass.as_deref() == Some("accept")
        {
            judge.recommended_next_pass = Some("polish_pass".to_string());
        }
        if judge.strongest_contradiction.is_none() {
            judge.strongest_contradiction = render_evaluation
                .findings
                .iter()
                .find(|finding| finding.severity == StudioArtifactRenderFindingSeverity::Warning)
                .map(|finding| finding.summary.clone())
                .or_else(|| Some(render_evaluation.summary.clone()));
        }
        if !judge
            .truthfulness_warnings
            .iter()
            .any(|value| value == &render_evaluation.summary)
        {
            judge
                .truthfulness_warnings
                .push(render_evaluation.summary.clone());
        }
    } else if render_evaluation.captures.len() >= 2
        && !judge
            .strengths
            .iter()
            .any(|value| value.contains("desktop and mobile render"))
    {
        judge.strengths.push(
            "Desktop and mobile render captures reinforced the surfaced hierarchy.".to_string(),
        );
    }

    if render_evaluation.overall_score <= render_evaluation.blocked_score_threshold()
        && request.renderer != StudioRendererKind::DownloadCard
        && request.renderer != StudioRendererKind::BundleManifest
    {
        judge.trivial_shell_detected = true;
    }

    if !judge.rationale.contains(&render_evaluation.summary) {
        judge.rationale = format!(
            "{} Render evaluation: {}",
            judge.rationale, render_evaluation.summary
        );
    }

    judge
}

fn render_blocking_finding_is_advisory_for_request(
    request: &StudioOutcomeArtifactRequest,
    finding: &StudioArtifactRenderFinding,
) -> bool {
    matches!(
        request.renderer,
        StudioRendererKind::Markdown | StudioRendererKind::PdfEmbed
    ) && finding.code == "typography_contrast_low"
}

fn average_u8(left: u8, right: u8) -> u8 {
    (((left as u16) + (right as u16)) / 2) as u8
}

fn merge_visual_score(model_score: u8, render_score: u8) -> u8 {
    if render_score + 1 < model_score {
        render_score.saturating_add(1)
    } else if render_score > model_score {
        model_score.saturating_add(1).min(render_score)
    } else {
        model_score
    }
}

fn candidate_renderable_path(request: &StudioOutcomeArtifactRequest) -> String {
    match request.renderer {
        StudioRendererKind::HtmlIframe => "index.html",
        StudioRendererKind::Svg => "artifact.svg",
        StudioRendererKind::Markdown => "artifact.md",
        StudioRendererKind::PdfEmbed => "artifact.pdf",
        StudioRendererKind::Mermaid => "artifact.mermaid",
        StudioRendererKind::JsxSandbox => "artifact.jsx",
        StudioRendererKind::DownloadCard => "download",
        StudioRendererKind::BundleManifest => "bundle.json",
        StudioRendererKind::WorkspaceSurface => "workspace",
    }
    .to_string()
}
