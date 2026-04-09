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

pub fn merge_studio_artifact_render_evaluation_into_judge(
    request: &StudioOutcomeArtifactRequest,
    mut judge: StudioArtifactJudgeResult,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
) -> StudioArtifactJudgeResult {
    if request.renderer == StudioRendererKind::HtmlIframe && studio_modal_first_html_enabled() {
        return judge;
    }
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

    let blocked_render_finding = render_evaluation
        .findings
        .iter()
        .find(|finding| finding.severity == StudioArtifactRenderFindingSeverity::Blocked);
    let warning_count = render_evaluation
        .findings
        .iter()
        .filter(|finding| finding.severity == StudioArtifactRenderFindingSeverity::Warning)
        .count();
    let render_clears_primary_view = render_evaluation.first_paint_captured
        && blocked_render_finding.is_none()
        && render_evaluation.overall_score >= 18;

    if !render_clears_primary_view {
        judge.deserves_primary_artifact_view = false;
    }

    if let Some(blocked) = blocked_render_finding {
        judge.classification = if render_evaluation.overall_score <= 9 {
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
    } else if warning_count > 0 || render_evaluation.overall_score < 18 {
        if judge.classification == StudioArtifactJudgeClassification::Pass {
            judge.classification = StudioArtifactJudgeClassification::Repairable;
        }
        judge.deserves_primary_artifact_view &= render_evaluation.overall_score >= 18;
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

    if render_evaluation.overall_score <= 9
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
