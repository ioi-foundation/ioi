use crate::models::{
    ChatArtifactLifecycleState, ChatOutcomeArtifactRequest, ChatRendererKind,
};
use ioi_api::runtime_harness::{
    ArtifactRenderEvaluation as ChatArtifactRenderEvaluation,
    ChatArtifactRenderFindingSeverity as ChatArtifactRenderFindingSeverity,
    ChatArtifactValidationResult as ChatArtifactValidationResult,
};

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
    pub(super) lifecycle_state: ChatArtifactLifecycleState,
    pub(super) summary: String,
    pub(super) findings: Vec<String>,
    pub(super) has_structural_blocker: bool,
}

fn chat_modal_first_html_enabled_for_request(request: &ChatOutcomeArtifactRequest) -> bool {
    request.renderer == ChatRendererKind::HtmlIframe
        && ioi_api::runtime_harness::chat_modal_first_html_enabled_for_tests_and_runtime()
}

pub(super) fn assess_materialized_artifact_presentation(
    request: &ChatOutcomeArtifactRequest,
    files: &[MaterializedArtifactQualityFile],
) -> ArtifactPresentationAssessment {
    let modal_first_html = chat_modal_first_html_enabled_for_request(request);
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
            message: "Chat did not materialize any files for the requested artifact.".to_string(),
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
        ChatRendererKind::Markdown => {
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
        ChatRendererKind::HtmlIframe => {
            let lower = primary_text.to_ascii_lowercase();
            if modal_first_html {
                if html_uses_external_runtime_dependency(&lower) {
                    has_structural_blocker = true;
                    issues.push(ArtifactPresentationIssue {
                        severity: ArtifactPresentationIssueSeverity::Blocked,
                        message: "HTML output depends on an external or undefined runtime library, so Render would not be truthful."
                            .to_string(),
                    });
                }
            } else {
                let semantic_sections =
                    ["<main", "<section", "<article", "<nav", "<aside", "<footer"]
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
                } else if html_uses_custom_font_family_without_loading(&lower) {
                    issues.push(ArtifactPresentationIssue {
                    severity: ArtifactPresentationIssueSeverity::Partial,
                    message: "HTML output names custom fonts without loading them, so typography truthfulness is still weak."
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
        }
        ChatRendererKind::JsxSandbox => {
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
        ChatRendererKind::Svg => {
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
                    message: "SVG output should include a stable viewBox before Chat treats it as fully presentation-ready."
                        .to_string(),
                });
            }
        }
        ChatRendererKind::Mermaid => {
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
        ChatRendererKind::PdfEmbed => {
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
        ChatRendererKind::DownloadCard => {
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
        ChatRendererKind::BundleManifest => {
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
        ChatRendererKind::WorkspaceSurface => {}
    }

    if let Some(primary_file) = primary_file {
        if primary_file.renderable
            && !(modal_first_html && request.renderer == ChatRendererKind::HtmlIframe)
            && request.renderer != ChatRendererKind::Mermaid
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
        ChatArtifactLifecycleState::Blocked
    } else if !issues.is_empty() {
        ChatArtifactLifecycleState::Partial
    } else {
        ChatArtifactLifecycleState::Ready
    };
    let findings = issues
        .iter()
        .map(|issue| issue.message.clone())
        .collect::<Vec<_>>();
    let summary = match lifecycle_state {
        ChatArtifactLifecycleState::Ready => {
            "Chat materialized the artifact and verified the render and presentation contract."
                .to_string()
        }
        ChatArtifactLifecycleState::Partial => format!(
            "Chat materialized the artifact, but presentation quality only reached partial: {}",
            findings
                .first()
                .cloned()
                .unwrap_or_else(|| "follow-up verification is still required.".to_string())
        ),
        ChatArtifactLifecycleState::Blocked => format!(
            "Chat materialized files, but blocked the primary presentation: {}",
            findings.first().cloned().unwrap_or_else(|| {
                "the artifact is not yet strong enough to lead the stage.".to_string()
            })
        ),
        _ => "Chat materialized the artifact.".to_string(),
    };

    ArtifactPresentationAssessment {
        lifecycle_state,
        summary,
        findings,
        has_structural_blocker,
    }
}

pub(super) fn finalize_presentation_assessment(
    request: &ChatOutcomeArtifactRequest,
    assessment: ArtifactPresentationAssessment,
    validation: &ChatArtifactValidationResult,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
    fallback_used: bool,
    draft_pending_acceptance: bool,
) -> ArtifactPresentationAssessment {
    let assessment = apply_render_evaluation_to_assessment(request, assessment, render_evaluation);
    let render_clears_primary_view =
        render_evaluation_clears_primary_view(request, render_evaluation);

    if draft_pending_acceptance {
        let mut findings = assessment.findings;
        let acceptance_reason = validation
            .strongest_contradiction
            .clone()
            .unwrap_or_else(|| "Acceptance validation remains pending for this draft.".to_string());
        if !findings.iter().any(|finding| finding == &acceptance_reason) {
            findings.push(acceptance_reason.clone());
        }
        let lifecycle_state = if assessment.has_structural_blocker
            || assessment.lifecycle_state == ChatArtifactLifecycleState::Blocked
        {
            ChatArtifactLifecycleState::Blocked
        } else {
            ChatArtifactLifecycleState::Partial
        };
        let summary = match lifecycle_state {
            ChatArtifactLifecycleState::Blocked => format!(
                "Chat materialized files, but blocked the primary presentation: {}",
                acceptance_reason
            ),
            _ => format!(
                "Chat surfaced a request-faithful draft while final acceptance validation remains pending: {}",
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
        && render_clears_primary_view
        && validation.classification
            == ioi_api::runtime_harness::ChatArtifactValidationStatus::Pass
        && validation.deserves_primary_artifact_view;

    if acceptance_clears_primary_view {
        let mut findings = assessment.findings;
        if !findings.is_empty() {
            findings.push(
                "Acceptance validation cleared the artifact for primary presentation despite softer prefilter findings."
                    .to_string(),
            );
        }

        return ArtifactPresentationAssessment {
            lifecycle_state: ChatArtifactLifecycleState::Ready,
            summary:
                "Chat materialized the artifact and final acceptance validation cleared it for the primary artifact view."
                    .to_string(),
            findings,
            has_structural_blocker: false,
        };
    }

    let acceptance_denies_primary_view = fallback_used
        || validation.classification
            != ioi_api::runtime_harness::ChatArtifactValidationStatus::Pass
        || !validation.deserves_primary_artifact_view
        || validation.generic_shell_detected
        || validation.trivial_shell_detected;
    if !acceptance_denies_primary_view {
        return assessment;
    }

    let mut findings = assessment.findings;
    let acceptance_reason = validation
        .strongest_contradiction
        .clone()
        .unwrap_or_else(|| {
            "Acceptance validation did not clear the artifact for primary presentation.".to_string()
        });
    if !findings.iter().any(|finding| finding == &acceptance_reason) {
        findings.push(acceptance_reason.clone());
    }

    let lifecycle_state = match validation.classification {
        ioi_api::runtime_harness::ChatArtifactValidationStatus::Blocked => {
            ChatArtifactLifecycleState::Blocked
        }
        _ => match assessment.lifecycle_state {
            ChatArtifactLifecycleState::Blocked => ChatArtifactLifecycleState::Blocked,
            _ => ChatArtifactLifecycleState::Partial,
        },
    };
    let summary = match lifecycle_state {
        ChatArtifactLifecycleState::Blocked => format!(
            "Chat materialized files, but acceptance validation blocked the primary presentation: {}",
            acceptance_reason
        ),
        ChatArtifactLifecycleState::Partial => format!(
            "Chat materialized the artifact, but acceptance validation kept it out of the primary view: {}",
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

fn apply_render_evaluation_to_assessment(
    request: &ChatOutcomeArtifactRequest,
    assessment: ArtifactPresentationAssessment,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> ArtifactPresentationAssessment {
    if chat_modal_first_html_enabled_for_request(request) {
        return assessment;
    }
    let Some(render_evaluation) = render_evaluation else {
        return assessment;
    };
    if !render_evaluation.supported {
        return assessment;
    }

    let mut findings = assessment.findings;
    for finding in &render_evaluation.findings {
        if !findings.iter().any(|value| value == &finding.summary) {
            findings.push(finding.summary.clone());
        }
    }
    if !findings
        .iter()
        .any(|value| value == &render_evaluation.summary)
    {
        findings.push(render_evaluation.summary.clone());
    }

    let has_warning_render_finding = render_evaluation
        .findings
        .iter()
        .any(|finding| finding.severity == ChatArtifactRenderFindingSeverity::Warning);
    let missing_interaction_capture =
        render_evaluation.interaction_capture_attempted && render_evaluation.captures.len() < 3;
    let blocked_by_render = render_evaluation.blocked_by_policy();
    let partial_due_to_render = !blocked_by_render
        && (has_warning_render_finding
            || render_evaluation.overall_score < render_evaluation.primary_view_score_threshold()
            || missing_interaction_capture);

    let mut lifecycle_state = assessment.lifecycle_state;
    if blocked_by_render {
        lifecycle_state = ChatArtifactLifecycleState::Blocked;
    } else if partial_due_to_render && lifecycle_state == ChatArtifactLifecycleState::Ready {
        lifecycle_state = ChatArtifactLifecycleState::Partial;
    }

    let has_structural_blocker = assessment.has_structural_blocker || blocked_by_render;
    let summary = if blocked_by_render {
        format!(
            "Chat materialized files, but render evaluation blocked the primary presentation: {}",
            render_evaluation.summary
        )
    } else if partial_due_to_render {
        match lifecycle_state {
            ChatArtifactLifecycleState::Partial => format!(
                "Chat materialized the artifact, but render evaluation kept it provisional: {}",
                render_evaluation.summary
            ),
            _ => assessment.summary,
        }
    } else {
        assessment.summary
    };

    ArtifactPresentationAssessment {
        lifecycle_state,
        summary,
        findings,
        has_structural_blocker,
    }
}

fn render_evaluation_clears_primary_view(
    request: &ChatOutcomeArtifactRequest,
    render_evaluation: Option<&ChatArtifactRenderEvaluation>,
) -> bool {
    if chat_modal_first_html_enabled_for_request(request) {
        return true;
    }
    let Some(render_evaluation) = render_evaluation else {
        return true;
    };
    if !render_evaluation.supported {
        return true;
    }

    render_evaluation.clears_primary_view_by_policy()
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
    false
}

fn html_uses_custom_font_family_without_loading(html_lower: &str) -> bool {
    if !html_lower.contains("font-family") {
        return false;
    }
    if html_lower.contains("fonts.googleapis.com")
        || html_lower.contains("@font-face")
        || html_lower.contains("font-face")
        || html_lower.contains("local(")
    {
        return false;
    }

    let mut cursor = 0usize;
    while let Some(relative_start) = html_lower[cursor..].find("font-family") {
        let start = cursor + relative_start;
        let Some(relative_colon) = html_lower[start..].find(':') else {
            break;
        };
        let value_start = start + relative_colon + 1;
        let declaration_end = html_lower[value_start..]
            .find(';')
            .map(|offset| value_start + offset)
            .or_else(|| {
                html_lower[value_start..]
                    .find('}')
                    .map(|offset| value_start + offset)
            })
            .unwrap_or(html_lower.len());
        let declaration = html_lower[value_start..declaration_end].trim();
        if declaration
            .split(',')
            .map(|segment| segment.trim().trim_matches('\'').trim_matches('"'))
            .filter(|segment| !segment.is_empty())
            .any(|segment| {
                !matches!(
                    segment,
                    "serif"
                        | "sans-serif"
                        | "monospace"
                        | "cursive"
                        | "fantasy"
                        | "system-ui"
                        | "ui-sans-serif"
                        | "ui-serif"
                        | "ui-monospace"
                        | "-apple-system"
                        | "blinkmacsystemfont"
                        | "segoe ui"
                        | "arial"
                        | "helvetica"
                        | "roboto"
                        | "georgia"
                        | "times new roman"
                        | "courier new"
                )
            })
        {
            return true;
        }
        cursor = declaration_end;
    }

    false
}

fn word_count(text: &str) -> usize {
    text.split_whitespace()
        .filter(|word| !word.trim().is_empty())
        .count()
}
