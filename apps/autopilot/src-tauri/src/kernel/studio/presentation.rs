use crate::models::{
    StudioArtifactLifecycleState, StudioOutcomeArtifactRequest, StudioRendererKind,
};
use ioi_api::studio::StudioArtifactJudgeResult;

pub(super) fn truncate_preview(content: &str) -> String {
    content
        .trim()
        .lines()
        .take(6)
        .collect::<Vec<_>>()
        .join("\n")
}

#[derive(Clone, Debug)]
pub(super) struct MaterializedArtifactQualityFile {
    pub(super) path: String,
    pub(super) mime: String,
    pub(super) renderable: bool,
    pub(super) downloadable: bool,
    pub(super) text_content: Option<String>,
}

#[derive(Clone, Debug)]
struct ArtifactPresentationIssue {
    severity: ArtifactPresentationIssueSeverity,
    message: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ArtifactPresentationIssueSeverity {
    Partial,
    Blocked,
}

#[derive(Clone, Debug)]
pub(super) struct ArtifactPresentationAssessment {
    pub(super) lifecycle_state: StudioArtifactLifecycleState,
    pub(super) summary: String,
    pub(super) findings: Vec<String>,
    pub(super) has_structural_blocker: bool,
}

pub(super) fn assess_materialized_artifact_presentation(
    request: &StudioOutcomeArtifactRequest,
    files: &[MaterializedArtifactQualityFile],
) -> ArtifactPresentationAssessment {
    let mut issues = Vec::new();
    let mut has_structural_blocker = false;
    let text_files = files
        .iter()
        .filter_map(|file| file.text_content.as_ref())
        .collect::<Vec<_>>();
    let primary_file = files
        .iter()
        .find(|file| file.renderable)
        .or_else(|| files.first());
    let primary_text = primary_file
        .and_then(|file| file.text_content.as_deref())
        .unwrap_or_default();
    let placeholder_hits = text_files
        .iter()
        .map(|text| placeholder_marker_hits(text))
        .sum::<usize>();

    if files.is_empty() {
        has_structural_blocker = true;
        issues.push(ArtifactPresentationIssue {
            severity: ArtifactPresentationIssueSeverity::Blocked,
            message: "Studio did not materialize any files for the requested artifact.".to_string(),
        });
    }

    if placeholder_hits >= 2 {
        has_structural_blocker = true;
        issues.push(ArtifactPresentationIssue {
            severity: ArtifactPresentationIssueSeverity::Blocked,
            message: "The primary artifact still reads like placeholder-grade output.".to_string(),
        });
    } else if placeholder_hits == 1 {
        issues.push(ArtifactPresentationIssue {
            severity: ArtifactPresentationIssueSeverity::Partial,
            message: "The artifact still contains placeholder copy that needs replacement."
                .to_string(),
        });
    }

    match request.renderer {
        StudioRendererKind::Markdown => {
            let headings = primary_text
                .lines()
                .filter(|line| line.trim_start().starts_with('#'))
                .count();
            let words = word_count(primary_text);
            if words < 45 {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Blocked,
                    message: "Markdown output is too thin to stand as the primary artifact view."
                        .to_string(),
                });
            } else if headings < 2 {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Partial,
                    message: "Markdown output needs clearer section structure before it should lead the artifact stage."
                        .to_string(),
                });
            }
        }
        StudioRendererKind::HtmlIframe => {
            let lower = primary_text.to_ascii_lowercase();
            let semantic_sections = ["<main", "<section", "<article", "<nav", "<aside", "<footer"]
                .iter()
                .map(|needle| lower.matches(needle).count())
                .sum::<usize>();
            let words = word_count(primary_text);
            if html_uses_external_runtime_dependency(&lower) {
                has_structural_blocker = true;
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Blocked,
                    message: "HTML output depends on an external or undefined runtime library, so Render would not be truthful."
                        .to_string(),
                });
            } else if words < 90 || semantic_sections < 3 {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Blocked,
                    message: "HTML output is still too skeletal to qualify as the primary rendered outcome."
                        .to_string(),
                });
            } else if !(lower.contains("<style") && words >= 140) {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Partial,
                    message: "HTML output renders, but it still needs stronger hierarchy or styling density."
                        .to_string(),
                });
            }
        }
        StudioRendererKind::JsxSandbox => {
            let words = word_count(primary_text);
            let control_tokens = [
                "<button", "<input", "<select", "<form", "onClick", "onChange", "useState",
            ]
            .iter()
            .map(|needle| primary_text.matches(needle).count())
            .sum::<usize>();
            let jsx_nodes = primary_text.matches('<').count();
            if words < 70 || jsx_nodes < 8 {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Blocked,
                    message:
                        "JSX output is too shallow to pass as a surfaced interactive artifact."
                            .to_string(),
                });
            } else if control_tokens < 2 {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Partial,
                    message: "JSX output needs clearer interactive affordances before Render should be the default stage."
                        .to_string(),
                });
            }
        }
        StudioRendererKind::Svg => {
            let lower = primary_text.to_ascii_lowercase();
            let shape_count = [
                "<path",
                "<rect",
                "<circle",
                "<ellipse",
                "<polygon",
                "<polyline",
                "<line",
                "<text",
            ]
            .iter()
            .map(|needle| lower.matches(needle).count())
            .sum::<usize>();
            if shape_count < 6 {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Blocked,
                    message: "SVG output is too sparse to stand as the primary visual artifact."
                        .to_string(),
                });
            } else if !lower.contains("viewbox") {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Partial,
                    message: "SVG output should include a stable viewBox before Studio treats it as fully presentation-ready."
                        .to_string(),
                });
            }
        }
        StudioRendererKind::Mermaid => {
            let edges = primary_text.matches("-->").count()
                + primary_text.matches("==>").count()
                + primary_text.matches("-.->").count();
            let nodes = primary_text.matches('[').count()
                + primary_text.matches('(').count()
                + primary_text.matches('{').count();
            if edges < 3 || nodes < 4 {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Blocked,
                    message: "Mermaid output is too small to justify leading the artifact stage."
                        .to_string(),
                });
            }
        }
        StudioRendererKind::PdfEmbed => {
            let words = word_count(primary_text);
            let paragraphs = primary_text
                .split("\n\n")
                .filter(|chunk| !chunk.trim().is_empty())
                .count();
            if words < 90 {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Blocked,
                    message: "PDF source content is too short to pass as a primary launch brief or report."
                        .to_string(),
                });
            } else if paragraphs < 4 {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Partial,
                    message: "PDF content should be broken into clearer sections before Render becomes the default."
                        .to_string(),
                });
            }
        }
        StudioRendererKind::DownloadCard => {
            let downloadable_count = files.iter().filter(|file| file.downloadable).count();
            let has_readme = files.iter().any(|file| {
                file.path.to_ascii_lowercase().contains("readme")
                    || file.mime.eq_ignore_ascii_case("text/markdown")
            });
            if downloadable_count == 0 {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Blocked,
                    message: "Download-card artifacts need at least one real downloadable file."
                        .to_string(),
                });
            } else if files.len() > 1 && !has_readme {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Partial,
                    message: "Multi-file downloads should include a README or orientation note."
                        .to_string(),
                });
            }
        }
        StudioRendererKind::BundleManifest => {
            let has_json_manifest = files.iter().any(|file| {
                file.path.to_ascii_lowercase().ends_with(".json")
                    && file.mime.eq_ignore_ascii_case("application/json")
            });
            if !has_json_manifest || files.len() < 2 {
                issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Blocked,
                    message:
                        "Bundle-manifest artifacts need a real manifest plus supporting files."
                            .to_string(),
                });
            }
        }
        StudioRendererKind::WorkspaceSurface => {}
    }

    if let Some(primary_file) = primary_file {
        if primary_file.renderable
            && request.renderer != StudioRendererKind::Mermaid
            && !primary_file.mime.to_ascii_lowercase().contains("svg")
            && word_count(primary_text) < 24
        {
            has_structural_blocker = true;
            issues.push(ArtifactPresentationIssue {
                severity: ArtifactPresentationIssueSeverity::Blocked,
                message: format!(
                    "Primary artifact file '{}' is too small to justify a successful surfaced outcome.",
                    primary_file.path
                ),
            });
        }
    }

    let lifecycle_state = if issues
        .iter()
        .any(|issue| issue.severity == ArtifactPresentationIssueSeverity::Blocked)
    {
        StudioArtifactLifecycleState::Blocked
    } else if !issues.is_empty() {
        StudioArtifactLifecycleState::Partial
    } else {
        StudioArtifactLifecycleState::Ready
    };
    let findings = issues
        .iter()
        .map(|issue| issue.message.clone())
        .collect::<Vec<_>>();
    let summary = match lifecycle_state {
        StudioArtifactLifecycleState::Ready => {
            "Studio materialized the artifact and verified the render and presentation contract."
                .to_string()
        }
        StudioArtifactLifecycleState::Partial => format!(
            "Studio materialized the artifact, but presentation quality only reached partial: {}",
            findings
                .first()
                .cloned()
                .unwrap_or_else(|| "follow-up verification is still required.".to_string())
        ),
        StudioArtifactLifecycleState::Blocked => format!(
            "Studio materialized files, but blocked the primary presentation: {}",
            findings.first().cloned().unwrap_or_else(|| {
                "the artifact is not yet strong enough to lead the stage.".to_string()
            })
        ),
        _ => "Studio materialized the artifact.".to_string(),
    };

    ArtifactPresentationAssessment {
        lifecycle_state,
        summary,
        findings,
        has_structural_blocker,
    }
}

pub(super) fn finalize_presentation_assessment(
    assessment: ArtifactPresentationAssessment,
    judge: &StudioArtifactJudgeResult,
    fallback_used: bool,
    draft_pending_acceptance: bool,
) -> ArtifactPresentationAssessment {
    if draft_pending_acceptance {
        let mut findings = assessment.findings;
        let acceptance_reason = judge.strongest_contradiction.clone().unwrap_or_else(|| {
            "Acceptance judging remains pending for this draft.".to_string()
        });
        if !findings.iter().any(|finding| finding == &acceptance_reason) {
            findings.push(acceptance_reason.clone());
        }
        let lifecycle_state = if assessment.has_structural_blocker
            || assessment.lifecycle_state == StudioArtifactLifecycleState::Blocked
        {
            StudioArtifactLifecycleState::Blocked
        } else {
            StudioArtifactLifecycleState::Partial
        };
        let summary = match lifecycle_state {
            StudioArtifactLifecycleState::Blocked => format!(
                "Studio materialized files, but blocked the primary presentation: {}",
                acceptance_reason
            ),
            _ => format!(
                "Studio surfaced a request-faithful draft while final acceptance judging remains pending: {}",
                acceptance_reason
            ),
        };

        return ArtifactPresentationAssessment {
            lifecycle_state,
            summary,
            findings,
            has_structural_blocker: assessment.has_structural_blocker,
        };
    }

    let acceptance_clears_primary_view = !fallback_used
        && !assessment.has_structural_blocker
        && judge.classification == ioi_api::studio::StudioArtifactJudgeClassification::Pass
        && judge.deserves_primary_artifact_view;

    if acceptance_clears_primary_view {
        let mut findings = assessment.findings;
        if !findings.is_empty() {
            findings.push(
                "Acceptance judging cleared the artifact for primary presentation despite softer prefilter findings."
                    .to_string(),
            );
        }

        return ArtifactPresentationAssessment {
            lifecycle_state: StudioArtifactLifecycleState::Ready,
            summary:
                "Studio materialized the artifact and final acceptance judging cleared it for the primary artifact view."
                    .to_string(),
            findings,
            has_structural_blocker: false,
        };
    }

    let acceptance_denies_primary_view = fallback_used
        || judge.classification != ioi_api::studio::StudioArtifactJudgeClassification::Pass
        || !judge.deserves_primary_artifact_view
        || judge.generic_shell_detected
        || judge.trivial_shell_detected;
    if !acceptance_denies_primary_view {
        return assessment;
    }

    let mut findings = assessment.findings;
    let acceptance_reason = judge.strongest_contradiction.clone().unwrap_or_else(|| {
        "Acceptance judging did not clear the artifact for primary presentation.".to_string()
    });
    if !findings.iter().any(|finding| finding == &acceptance_reason) {
        findings.push(acceptance_reason.clone());
    }

    let lifecycle_state = match judge.classification {
        ioi_api::studio::StudioArtifactJudgeClassification::Blocked => {
            StudioArtifactLifecycleState::Blocked
        }
        _ => match assessment.lifecycle_state {
            StudioArtifactLifecycleState::Blocked => StudioArtifactLifecycleState::Blocked,
            _ => StudioArtifactLifecycleState::Partial,
        },
    };
    let summary = match lifecycle_state {
        StudioArtifactLifecycleState::Blocked => format!(
            "Studio materialized files, but acceptance judging blocked the primary presentation: {}",
            acceptance_reason
        ),
        StudioArtifactLifecycleState::Partial => format!(
            "Studio materialized the artifact, but acceptance judging kept it out of the primary view: {}",
            acceptance_reason
        ),
        _ => assessment.summary,
    };

    ArtifactPresentationAssessment {
        lifecycle_state,
        summary,
        findings,
        has_structural_blocker: assessment.has_structural_blocker,
    }
}

fn placeholder_marker_hits(text: &str) -> usize {
    let lower = text.to_ascii_lowercase();
    [
        "placeholder",
        "lorem ipsum",
        "todo",
        "tbd",
        "coming soon",
        "replace this",
        "sample text",
    ]
    .iter()
    .filter(|needle| lower.contains(**needle))
    .count()
}

fn html_uses_external_runtime_dependency(html_lower: &str) -> bool {
    if html_lower.contains("<script src=")
        || html_lower.contains("<script src='")
        || html_lower.contains("<link rel=")
        || html_lower.contains("<link rel='")
    {
        return true;
    }

    let d3_defined_locally = ["const d3", "let d3", "var d3", "function d3", "class d3"]
        .iter()
        .any(|needle| html_lower.contains(needle));
    if html_lower.contains("d3.") && !d3_defined_locally {
        return true;
    }

    let chart_defined_locally = [
        "const chart",
        "let chart",
        "var chart",
        "function chart",
        "class chart",
    ]
    .iter()
    .any(|needle| html_lower.contains(needle));
    html_lower.contains("new chart(") && !chart_defined_locally
}

fn word_count(text: &str) -> usize {
    text.split_whitespace()
        .filter(|word| !word.trim().is_empty())
        .count()
}
