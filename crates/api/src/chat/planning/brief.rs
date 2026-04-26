use super::shared::{
    brief_field_repair_max_tokens_for_runtime, brief_planner_max_tokens_for_runtime,
    brief_repair_max_tokens_for_runtime, chat_planning_trace, compact_local_html_brief_prompt,
    outcome_artifact_renderer_defaults, truncate_planning_preview,
};
use crate::chat::validation::chat_artifact_refinement_context_view;
use crate::chat::*;
use crate::vm::inference::InferenceRuntime;
use ioi_types::app::agentic::InferenceOptions;
use ioi_types::app::{ChatOutcomeArtifactRequest, ChatRendererKind, ChatRuntimeProvenanceKind};
use serde_json::json;
use std::sync::Arc;

pub async fn plan_chat_artifact_brief_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
) -> Result<ChatArtifactBrief, String> {
    let runtime_provenance = runtime.chat_runtime_provenance();
    let parse_and_validate = |raw: &str| -> Result<ChatArtifactBrief, String> {
        let brief =
            canonicalize_chat_artifact_brief_for_request(parse_chat_artifact_brief(raw)?, request);
        validate_chat_artifact_brief_against_request(&brief, request, refinement)?;
        Ok(brief)
    };
    let empty_core_fields_error = "Chat artifact brief fields must not be empty.";
    let salvage_and_validate = |raw: &str| -> Result<ChatArtifactBrief, String> {
        let brief = salvage_chat_artifact_brief_core_fields(raw, title, intent, request)?;
        validate_chat_artifact_brief_against_request(&brief, request, refinement)?;
        Ok(brief)
    };
    let compact_local_brief_contract =
        compact_local_html_brief_prompt(request.renderer, runtime_provenance.kind);
    let planner_max_tokens =
        brief_planner_max_tokens_for_runtime(request.renderer, runtime_provenance.kind);
    let payload = build_chat_artifact_brief_prompt_for_runtime(
        title,
        intent,
        request,
        refinement,
        runtime_provenance.kind,
    )?;
    let input = serde_json::to_vec(&payload)
        .map_err(|error| format!("Failed to encode Chat artifact brief prompt: {error}"))?;
    chat_planning_trace(format!(
        "artifact_brief:start renderer={:?} runtime={} model={:?} prompt_bytes={} max_tokens={} json_mode={}",
        request.renderer,
        runtime_provenance.label,
        runtime_provenance.model,
        input.len(),
        planner_max_tokens,
        !compact_local_brief_contract
    ));
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: 0.0,
                json_mode: !compact_local_brief_contract,
                max_tokens: planner_max_tokens,
                ..Default::default()
            },
        )
        .await
        .map_err(|error| format!("Chat artifact brief inference failed: {error}"))?;
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Chat artifact brief utf8 decode failed: {error}"))?;
    chat_planning_trace(format!(
        "artifact_brief:planner_output {}",
        truncate_planning_preview(&raw, 1200)
    ));
    match parse_and_validate(&raw) {
        Ok(brief) => Ok(brief),
        Err(first_error) => {
            chat_planning_trace(format!("artifact_brief:planner_rejected {first_error}"));
            if first_error.contains(empty_core_fields_error) {
                if let Ok(brief) = salvage_and_validate(&raw) {
                    chat_planning_trace("artifact_brief:planner_salvaged");
                    return Ok(brief);
                }
            }
            let repair_payload = build_chat_artifact_brief_repair_prompt_for_runtime(
                title,
                intent,
                request,
                refinement,
                &raw,
                &first_error,
                runtime_provenance.kind,
            )?;
            let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                format!("Failed to encode Chat artifact brief repair prompt: {error}")
            })?;
            let repair_max_tokens =
                brief_repair_max_tokens_for_runtime(request.renderer, runtime_provenance.kind);
            chat_planning_trace(format!(
                "artifact_brief:repair_start renderer={:?} runtime={} model={:?} prompt_bytes={} max_tokens={} json_mode={} failure={}",
                request.renderer,
                runtime_provenance.label,
                runtime_provenance.model,
                repair_input.len(),
                repair_max_tokens,
                !compact_local_brief_contract,
                truncate_planning_preview(&first_error, 240)
            ));
            let repair_output = runtime
                .execute_inference(
                    [0u8; 32],
                    &repair_input,
                    InferenceOptions {
                        temperature: 0.0,
                        json_mode: !compact_local_brief_contract,
                        max_tokens: repair_max_tokens,
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| {
                    format!("{first_error}; brief repair inference failed: {error}")
                })?;
            let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                format!("{first_error}; brief repair utf8 decode failed: {error}")
            })?;
            chat_planning_trace(format!(
                "artifact_brief:repair_output {}",
                truncate_planning_preview(&repair_raw, 1200)
            ));
            match parse_and_validate(&repair_raw) {
                Ok(brief) => Ok(brief),
                Err(repair_error) => {
                    chat_planning_trace(format!("artifact_brief:repair_rejected {repair_error}"));
                    let field_repair_payload = if compact_local_html_brief_prompt(
                        request.renderer,
                        runtime_provenance.kind,
                    ) {
                        build_chat_artifact_brief_field_repair_prompt_for_runtime(
                            title,
                            intent,
                            request,
                            refinement,
                            &raw,
                            &repair_raw,
                            &repair_error,
                            runtime_provenance.kind,
                        )?
                    } else {
                        build_chat_artifact_brief_field_repair_prompt(
                            title,
                            intent,
                            request,
                            refinement,
                            &raw,
                            &repair_raw,
                            &repair_error,
                        )?
                    };
                    let field_repair_input =
                        serde_json::to_vec(&field_repair_payload).map_err(|error| {
                            format!(
                                "Failed to encode Chat artifact brief field repair prompt: {error}"
                            )
                        })?;
                    let field_repair_max_tokens = brief_field_repair_max_tokens_for_runtime(
                        request.renderer,
                        runtime_provenance.kind,
                    );
                    chat_planning_trace(format!(
                        "artifact_brief:field_repair_start renderer={:?} runtime={} model={:?} prompt_bytes={} max_tokens={} json_mode={} failure={}",
                        request.renderer,
                        runtime_provenance.label,
                        runtime_provenance.model,
                        field_repair_input.len(),
                        field_repair_max_tokens,
                        !compact_local_brief_contract,
                        truncate_planning_preview(&repair_error, 240)
                    ));
                    let field_repair_output = runtime
                        .execute_inference(
                            [0u8; 32],
                            &field_repair_input,
                            InferenceOptions {
                                temperature: 0.0,
                                json_mode: !compact_local_brief_contract,
                                max_tokens: field_repair_max_tokens,
                                ..Default::default()
                            },
                        )
                        .await
                        .map_err(|error| {
                            format!(
                                "{first_error}; brief repair attempt failed: {repair_error}; brief field repair inference failed: {error}"
                            )
                        })?;
                    let field_repair_raw =
                        String::from_utf8(field_repair_output).map_err(|error| {
                            format!(
                                "{first_error}; brief repair attempt failed: {repair_error}; brief field repair utf8 decode failed: {error}"
                            )
                        })?;
                    chat_planning_trace(format!(
                        "artifact_brief:field_repair_output {}",
                        truncate_planning_preview(&field_repair_raw, 1200)
                    ));
                    parse_and_validate(&field_repair_raw)
                        .or_else(|field_repair_error| {
                            salvage_and_validate(&field_repair_raw).map_err(|salvage_error| {
                                format!(
                                    "{first_error}; brief repair attempt failed: {repair_error}; brief field repair attempt also failed: {field_repair_error}; deterministic salvage also failed: {salvage_error}; planner output preview: {}; repair output preview: {}; field repair output preview: {}",
                                    truncate_planning_preview(&raw, 600),
                                    truncate_planning_preview(&repair_raw, 600),
                                    truncate_planning_preview(&field_repair_raw, 600),
                                )
                            })
                        })
                }
            }
        }
    }
}

fn request_grounded_subject_domain(title: &str, intent: &str) -> String {
    derive_brief_subject_domain(
        &ChatArtifactBrief {
            audience: String::new(),
            job_to_be_done: String::new(),
            subject_domain: String::new(),
            artifact_thesis: String::new(),
            required_concepts: Vec::new(),
            required_interactions: Vec::new(),
            query_profile: None,
            visual_tone: Vec::new(),
            factual_anchors: Vec::new(),
            style_directives: Vec::new(),
            reference_hints: Vec::new(),
        },
        title,
        intent,
    )
    .unwrap_or_else(|| {
        let fallback = trim_sentence_terminal(intent);
        if fallback.is_empty() {
            "the requested artifact".to_string()
        } else {
            fallback
        }
    })
}

fn request_grounded_primary_anchor(title: &str, subject_domain: &str) -> String {
    let title_candidate = trim_sentence_terminal(title);
    if !title_candidate.is_empty() && !title_is_too_generic_for_subject_domain(&title_candidate) {
        title_candidate
    } else {
        subject_domain.to_string()
    }
}

fn starts_with_request_directive(value: &str) -> bool {
    matches!(
        value
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase()
            .as_str(),
        "build"
            | "create"
            | "craft"
            | "design"
            | "draft"
            | "generate"
            | "give"
            | "make"
            | "prepare"
            | "produce"
            | "show"
            | "write"
    )
}

fn split_once_case_insensitive<'a>(value: &'a str, needle: &str) -> Option<(&'a str, &'a str)> {
    let lowercase = value.to_ascii_lowercase();
    lowercase
        .find(needle)
        .map(|index| (&value[..index], &value[index + needle.len()..]))
}

fn trim_leading_article_phrase(value: &str) -> String {
    let trimmed = value.trim();
    for prefix in ["a ", "an ", "the "] {
        if trimmed.len() >= prefix.len() && trimmed[..prefix.len()].eq_ignore_ascii_case(prefix) {
            return trimmed[prefix.len()..].trim().to_string();
        }
    }
    trimmed.to_string()
}

fn is_bullet_count_token(token: &str) -> bool {
    token.chars().all(|character| character.is_ascii_digit())
        || matches!(
            token,
            "one"
                | "two"
                | "three"
                | "four"
                | "five"
                | "six"
                | "seven"
                | "eight"
                | "nine"
                | "ten"
                | "eleven"
                | "twelve"
        )
}

fn strip_trailing_bullet_constraint(value: &str) -> String {
    let trimmed = trim_sentence_terminal(value);
    let lowercase = trimmed.to_ascii_lowercase();
    let Some(index) = lowercase.rfind(" in ") else {
        return trimmed;
    };
    let tail = lowercase[index + 4..].trim();
    let parts = tail.split_whitespace().collect::<Vec<_>>();
    if parts.len() == 2
        && is_bullet_count_token(parts[0])
        && matches!(parts[1], "bullet" | "bullets")
    {
        return trim_sentence_terminal(&trimmed[..index]);
    }
    trimmed
}

fn strip_trailing_renderer_constraint(value: &str) -> String {
    let trimmed = trim_sentence_terminal(value);
    let lowercase = trimmed.to_ascii_lowercase();
    for suffix in [
        " as markdown",
        " in markdown",
        " using markdown",
        " as html",
        " in html",
        " using html",
        " as pdf",
        " in pdf",
        " using pdf",
        " as svg",
        " in svg",
        " using svg",
        " as mermaid",
        " in mermaid",
        " using mermaid",
        " as a mermaid diagram",
        " in a mermaid diagram",
    ] {
        if lowercase.ends_with(suffix) {
            return trim_sentence_terminal(&trimmed[..trimmed.len() - suffix.len()]);
        }
    }
    trimmed
}

fn clean_request_subject_clause(value: &str) -> String {
    let without_article = trim_leading_article_phrase(value);
    let without_bullets = strip_trailing_bullet_constraint(&without_article);
    let without_renderer = strip_trailing_renderer_constraint(&without_bullets);
    normalize_inline_whitespace(&without_renderer)
}

fn request_subject_candidate_from_intent(intent: &str) -> Option<String> {
    let normalized_intent = normalize_inline_whitespace(intent);
    if normalized_intent.is_empty() || !starts_with_request_directive(&normalized_intent) {
        return None;
    }

    for marker in [
        " that explains ",
        " that explain ",
        " explaining ",
        " explain ",
        " about ",
        " on ",
        " of ",
        " for ",
    ] {
        let Some((preamble, tail)) = split_once_case_insensitive(&normalized_intent, marker) else {
            continue;
        };
        if !starts_with_request_directive(preamble) {
            continue;
        }
        let candidate = clean_request_subject_clause(tail);
        if !candidate.is_empty() && !starts_with_request_directive(&candidate) {
            return Some(candidate);
        }
    }

    None
}

fn request_job_candidate_from_intent(intent: &str) -> Option<String> {
    let normalized_intent = normalize_inline_whitespace(intent);
    if normalized_intent.is_empty() || !starts_with_request_directive(&normalized_intent) {
        return None;
    }

    for (marker, verb) in [
        (" that explains ", "explain"),
        (" that explain ", "explain"),
        (" explaining ", "explain"),
        (" explain ", "explain"),
        (" about ", "summarize"),
        (" on ", "summarize"),
        (" of ", "show"),
        (" for ", "present"),
    ] {
        let Some((preamble, tail)) = split_once_case_insensitive(&normalized_intent, marker) else {
            continue;
        };
        if !starts_with_request_directive(preamble) {
            continue;
        }
        let clause = normalize_inline_whitespace(&trim_leading_article_phrase(tail));
        if !clause.is_empty() && !starts_with_request_directive(&clause) {
            return Some(format!("{verb} {}", trim_sentence_terminal(&clause)));
        }
    }

    None
}

fn request_grounded_job_to_be_done(
    request: &ChatOutcomeArtifactRequest,
    subject_domain: &str,
    intent: &str,
) -> String {
    let normalized_intent = trim_sentence_terminal(intent);
    if !normalized_intent.is_empty() {
        if let Some(candidate) = request_job_candidate_from_intent(&normalized_intent) {
            return candidate;
        }
        return normalized_intent;
    }

    match request.renderer {
        ChatRendererKind::HtmlIframe => {
            format!("understand {subject_domain} through an interactive artifact")
        }
        ChatRendererKind::JsxSandbox => {
            format!("explore {subject_domain} through an interactive surface")
        }
        ChatRendererKind::Svg | ChatRendererKind::Mermaid => {
            format!("understand {subject_domain} at a glance")
        }
        ChatRendererKind::Markdown | ChatRendererKind::PdfEmbed => {
            format!("review {subject_domain} clearly")
        }
        ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest => {
            format!("download the useful {subject_domain} fileset")
        }
        ChatRendererKind::WorkspaceSurface => {
            "scaffold a working implementation surface".to_string()
        }
    }
}

fn request_grounded_required_concepts(
    request: &ChatOutcomeArtifactRequest,
    subject_domain: &str,
) -> Vec<String> {
    let mut concepts = vec![subject_domain.to_string()];
    match request.renderer {
        ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox => {
            concepts.push(format!("{subject_domain} fundamentals"));
            concepts.push(format!("{subject_domain} examples"));
            concepts.push(format!("{subject_domain} comparisons"));
        }
        ChatRendererKind::Svg | ChatRendererKind::Mermaid => {
            concepts.push(format!("{subject_domain} overview"));
            concepts.push(format!("{subject_domain} relationships"));
        }
        ChatRendererKind::Markdown | ChatRendererKind::PdfEmbed => {
            concepts.push(format!("{subject_domain} summary"));
            concepts.push(format!("{subject_domain} evidence"));
        }
        ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest => {
            concepts.push(format!("{subject_domain} files"));
            concepts.push(format!("{subject_domain} usage"));
        }
        ChatRendererKind::WorkspaceSurface => {
            concepts.push(format!("{subject_domain} interface"));
            concepts.push(format!("{subject_domain} implementation"));
        }
    }
    canonicalize_brief_list(concepts)
}

fn request_grounded_query_profile(
    request: &ChatOutcomeArtifactRequest,
    subject_domain: &str,
) -> ChatArtifactQueryProfile {
    let mut content_goals = vec![
        ChatArtifactContentGoal {
            kind: ChatArtifactContentGoalKind::Orient,
            summary: format!("Orient the user to {subject_domain} immediately."),
            required: true,
        },
        ChatArtifactContentGoal {
            kind: ChatArtifactContentGoalKind::Explain,
            summary: format!("Explain the core ideas behind {subject_domain}."),
            required: true,
        },
    ];
    let mut evidence_goals = vec![ChatArtifactEvidenceGoal {
        kind: ChatArtifactEvidenceGoalKind::PrimarySurface,
        summary: "Keep one grounded evidence surface visible on first paint.".to_string(),
        required: true,
    }];
    let mut interaction_goals = Vec::<ChatArtifactInteractionGoal>::new();
    let mut presentation_constraints = vec![
        ChatArtifactPresentationConstraint {
            kind: ChatArtifactPresentationConstraintKind::SemanticStructure,
            summary: "Use semantic structure so the primary surface is legible before enhancement."
                .to_string(),
            required: true,
        },
        ChatArtifactPresentationConstraint {
            kind: ChatArtifactPresentationConstraintKind::FirstPaintEvidence,
            summary: "Populate the first paint with meaningful content rather than empty shells."
                .to_string(),
            required: true,
        },
        ChatArtifactPresentationConstraint {
            kind: ChatArtifactPresentationConstraintKind::RuntimeSelfContainment,
            summary: "Keep the artifact self-contained and renderable without external runtime assumptions."
                .to_string(),
            required: true,
        },
    ];

    match request.renderer {
        ChatRendererKind::HtmlIframe => {
            if request.artifact_class == ChatArtifactClass::InteractiveSingleFile {
                content_goals.push(ChatArtifactContentGoal {
                    kind: ChatArtifactContentGoalKind::Compare,
                    summary: format!("Let the user compare multiple angles of {subject_domain}."),
                    required: true,
                });
                evidence_goals.push(ChatArtifactEvidenceGoal {
                    kind: ChatArtifactEvidenceGoalKind::ComparisonSurface,
                    summary:
                        "Keep at least one alternate evidence surface pre-rendered for comparison."
                            .to_string(),
                    required: true,
                });
                interaction_goals.extend([
                    ChatArtifactInteractionGoal {
                        kind: ChatArtifactInteractionGoalKind::StateSwitch,
                        summary: format!(
                            "Switch between authored states to compare how the explanation of {subject_domain} changes."
                        ),
                        required: true,
                    },
                    ChatArtifactInteractionGoal {
                        kind: ChatArtifactInteractionGoalKind::DetailInspect,
                        summary: format!(
                            "Inspect visible evidence to reveal more context about {subject_domain} inline."
                        ),
                        required: true,
                    },
                    ChatArtifactInteractionGoal {
                        kind: ChatArtifactInteractionGoalKind::SequenceBrowse,
                        summary: format!(
                            "Progress through staged evidence or examples so the {subject_domain} story unfolds step by step."
                        ),
                        required: false,
                    },
                ]);
                presentation_constraints.extend([
                    ChatArtifactPresentationConstraint {
                        kind: ChatArtifactPresentationConstraintKind::ResponseRegion,
                        summary: "Keep one shared response or explanation region visible while interactions run."
                            .to_string(),
                        required: true,
                    },
                    ChatArtifactPresentationConstraint {
                        kind: ChatArtifactPresentationConstraintKind::KeyboardAffordances,
                        summary: "Expose keyboard-reachable affordances for the primary interactive surfaces."
                            .to_string(),
                        required: true,
                    },
                    ChatArtifactPresentationConstraint {
                        kind: ChatArtifactPresentationConstraintKind::TypographySeparation,
                        summary: "Create clear typographic separation between framing, evidence, and response surfaces."
                            .to_string(),
                        required: false,
                    },
                ]);
            } else {
                content_goals.push(ChatArtifactContentGoal {
                    kind: ChatArtifactContentGoalKind::Summary,
                    summary: format!("Deliver a clear single-pass explainer for {subject_domain}."),
                    required: true,
                });
                evidence_goals.push(ChatArtifactEvidenceGoal {
                    kind: ChatArtifactEvidenceGoalKind::SupportingSurface,
                    summary: "Keep one supporting comparison or evidence surface visible without requiring interaction."
                        .to_string(),
                    required: false,
                });
                presentation_constraints.push(ChatArtifactPresentationConstraint {
                    kind: ChatArtifactPresentationConstraintKind::TypographySeparation,
                    summary: "Create clear typographic separation between framing copy, evidence, and supporting notes."
                        .to_string(),
                    required: false,
                });
            }
        }
        ChatRendererKind::JsxSandbox => {
            content_goals.push(ChatArtifactContentGoal {
                kind: ChatArtifactContentGoalKind::Implementation,
                summary: format!("Expose a working interactive surface for {subject_domain}."),
                required: true,
            });
            interaction_goals.extend([
                ChatArtifactInteractionGoal {
                    kind: ChatArtifactInteractionGoalKind::StateAdjust,
                    summary: format!(
                        "Adjust controls to update the visible response for {subject_domain}."
                    ),
                    required: true,
                },
                ChatArtifactInteractionGoal {
                    kind: ChatArtifactInteractionGoalKind::DetailInspect,
                    summary: format!(
                        "Inspect visible state details to understand the current {subject_domain} response."
                    ),
                    required: true,
                },
            ]);
            presentation_constraints.extend([
                ChatArtifactPresentationConstraint {
                    kind: ChatArtifactPresentationConstraintKind::ResponseRegion,
                    summary: "Keep a visible response region on first paint so state changes stay interpretable."
                        .to_string(),
                    required: true,
                },
                ChatArtifactPresentationConstraint {
                    kind: ChatArtifactPresentationConstraintKind::KeyboardAffordances,
                    summary: "Provide keyboard-reachable controls for the interactive demo surface."
                        .to_string(),
                    required: true,
                },
            ]);
        }
        ChatRendererKind::Svg | ChatRendererKind::Mermaid => {
            content_goals.push(ChatArtifactContentGoal {
                kind: ChatArtifactContentGoalKind::Summary,
                summary: format!("Summarize {subject_domain} at a glance."),
                required: true,
            });
            evidence_goals.push(ChatArtifactEvidenceGoal {
                kind: ChatArtifactEvidenceGoalKind::SupportingSurface,
                summary: "Use labeled supporting marks so the visual remains self-explanatory."
                    .to_string(),
                required: true,
            });
            presentation_constraints.push(ChatArtifactPresentationConstraint {
                kind: ChatArtifactPresentationConstraintKind::TypographySeparation,
                summary:
                    "Use strong labeling and hierarchy so the visual reads without extra narration."
                        .to_string(),
                required: true,
            });
        }
        ChatRendererKind::Markdown | ChatRendererKind::PdfEmbed => {
            content_goals.push(ChatArtifactContentGoal {
                kind: ChatArtifactContentGoalKind::Summary,
                summary: format!("Summarize {subject_domain} clearly and with grounded evidence."),
                required: true,
            });
            evidence_goals.push(ChatArtifactEvidenceGoal {
                kind: ChatArtifactEvidenceGoalKind::SupportingSurface,
                summary: "Support the document with grounded evidence and explicit takeaways."
                    .to_string(),
                required: true,
            });
        }
        ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest => {
            content_goals.push(ChatArtifactContentGoal {
                kind: ChatArtifactContentGoalKind::Implementation,
                summary: format!(
                    "Package the useful {subject_domain} fileset with clear orientation."
                ),
                required: true,
            });
        }
        ChatRendererKind::WorkspaceSurface => {
            content_goals.push(ChatArtifactContentGoal {
                kind: ChatArtifactContentGoalKind::Implementation,
                summary: "Expose a working implementation surface and scaffolding cues."
                    .to_string(),
                required: true,
            });
        }
    }

    ChatArtifactQueryProfile {
        content_goals,
        interaction_goals,
        evidence_goals,
        presentation_constraints,
    }
}

fn request_grounded_required_interactions(
    request: &ChatOutcomeArtifactRequest,
    _subject_domain: &str,
    query_profile: &ChatArtifactQueryProfile,
) -> Vec<String> {
    let interactions = query_profile
        .interaction_goals
        .iter()
        .map(|goal| goal.summary.clone())
        .collect::<Vec<_>>();

    canonicalize_brief_interactions(interactions, request)
}

fn request_grounded_visual_tone(request: &ChatOutcomeArtifactRequest) -> Vec<String> {
    canonicalize_brief_list(match request.renderer {
        ChatRendererKind::HtmlIframe => vec![
            "bold editorial contrast".to_string(),
            "technical explainer clarity".to_string(),
        ],
        ChatRendererKind::JsxSandbox => vec![
            "product-grade interface clarity".to_string(),
            "interaction-led hierarchy".to_string(),
        ],
        ChatRendererKind::Svg | ChatRendererKind::Mermaid => {
            vec!["diagram-led clarity".to_string()]
        }
        _ => vec!["grounded document clarity".to_string()],
    })
}

fn request_grounded_style_directives(request: &ChatOutcomeArtifactRequest) -> Vec<String> {
    canonicalize_brief_list(match request.renderer {
        ChatRendererKind::HtmlIframe => {
            if request.artifact_class == ChatArtifactClass::InteractiveSingleFile {
                vec![
                    "request-shaped hierarchy".to_string(),
                    "clear interaction affordances".to_string(),
                ]
            } else {
                vec![
                    "request-shaped hierarchy".to_string(),
                    "clear evidence framing".to_string(),
                ]
            }
        }
        ChatRendererKind::JsxSandbox => vec![
            "request-shaped hierarchy".to_string(),
            "clear interaction affordances".to_string(),
        ],
        ChatRendererKind::Svg | ChatRendererKind::Mermaid => {
            vec!["strong visual labeling".to_string()]
        }
        _ => vec!["clear hierarchy".to_string()],
    })
}

pub fn derive_request_grounded_chat_artifact_brief(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
) -> ChatArtifactBrief {
    let user_intent = extract_user_request_from_contextualized_intent(intent);
    let title_seed = if title.trim().starts_with("[Codebase context]") {
        user_intent.as_str()
    } else {
        title
    };
    let subject_domain = request_grounded_subject_domain(title_seed, &user_intent);
    let primary_anchor = request_grounded_primary_anchor(title_seed, &subject_domain);
    let mut factual_anchors =
        canonicalize_brief_list(vec![primary_anchor, format!("{subject_domain} examples")]);
    if let Some(refinement) = refinement {
        factual_anchors = canonicalize_brief_list({
            let mut anchors = factual_anchors;
            anchors.push(refinement.title.trim().to_string());
            anchors
        });
    }
    let reference_hints = canonicalize_brief_list(
        if request.renderer == ChatRendererKind::HtmlIframe
            && request.artifact_class != ChatArtifactClass::InteractiveSingleFile
        {
            vec![
                format!("{subject_domain} basics"),
                format!("{subject_domain} examples"),
            ]
        } else {
            vec![
                format!("{subject_domain} comparisons"),
                format!("{subject_domain} evidence"),
            ]
        },
    );
    let query_profile = request_grounded_query_profile(request, &subject_domain);

    let brief = ChatArtifactBrief {
        audience: derive_brief_audience(request, &subject_domain)
            .unwrap_or_else(|| "people exploring the request".to_string()),
        job_to_be_done: request_grounded_job_to_be_done(request, &subject_domain, &user_intent),
        subject_domain: subject_domain.clone(),
        artifact_thesis: match request.renderer {
            ChatRendererKind::HtmlIframe => {
                if request.artifact_class == ChatArtifactClass::InteractiveSingleFile {
                    format!(
                        "Explain {subject_domain} through visible evidence, grounded comparisons, and request-faithful interaction."
                    )
                } else {
                    format!(
                        "Explain {subject_domain} through visible evidence and a clear authored HTML reading experience."
                    )
                }
            }
            ChatRendererKind::JsxSandbox => format!(
                "Explain {subject_domain} through visible evidence, grounded comparisons, and request-faithful interaction."
            ),
            ChatRendererKind::Svg | ChatRendererKind::Mermaid => format!(
                "Make {subject_domain} understandable at a glance through a clear visual spine."
            ),
            _ => derive_brief_artifact_thesis(request, &subject_domain)
                .unwrap_or_else(|| format!("A {subject_domain} artifact")),
        },
        required_concepts: request_grounded_required_concepts(request, &subject_domain),
        required_interactions: request_grounded_required_interactions(
            request,
            &subject_domain,
            &query_profile,
        ),
        query_profile: Some(query_profile),
        visual_tone: request_grounded_visual_tone(request),
        factual_anchors,
        style_directives: request_grounded_style_directives(request),
        reference_hints,
    };
    let canonical = canonicalize_chat_artifact_brief_for_request(brief, request);
    debug_assert!(
        validate_chat_artifact_brief_against_request(&canonical, request, refinement).is_ok(),
        "request-grounded artifact brief must satisfy Chat validation"
    );
    canonical
}

fn push_unique_brief_note(values: &mut Vec<String>, value: String) {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return;
    }
    if !values
        .iter()
        .any(|existing| existing.eq_ignore_ascii_case(trimmed))
    {
        values.push(trimmed.to_string());
    }
}

pub fn apply_artifact_connector_grounding_to_brief(
    brief: &mut ChatArtifactBrief,
    connector_grounding: Option<&ArtifactConnectorGrounding>,
) {
    let Some(connector_grounding) = connector_grounding else {
        return;
    };

    push_unique_brief_note(
        &mut brief.factual_anchors,
        "selected connector data is the grounding source".to_string(),
    );
    push_unique_brief_note(
        &mut brief.reference_hints,
        "ground the artifact in the selected connector content, not generic examples".to_string(),
    );

    if let Some(target_label) = connector_grounding.target_label.as_ref() {
        push_unique_brief_note(
            &mut brief.factual_anchors,
            format!("selected connector target: {}", target_label.trim()),
        );
    }
    if let Some(connector_id) = connector_grounding.connector_id.as_ref() {
        push_unique_brief_note(
            &mut brief.reference_hints,
            format!("selected connector id: {}", connector_id.trim()),
        );
    }
    if let Some(provider_family) = connector_grounding.provider_family.as_ref() {
        push_unique_brief_note(
            &mut brief.reference_hints,
            format!("selected provider family: {}", provider_family.trim()),
        );
    }
}

pub async fn synthesize_chat_artifact_brief_for_execution_strategy_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    execution_strategy: ChatExecutionStrategy,
) -> Result<ChatArtifactBrief, String> {
    if execution_strategy == ChatExecutionStrategy::DirectAuthor {
        return Ok(derive_request_grounded_chat_artifact_brief(
            title, intent, request, refinement,
        ));
    }

    plan_chat_artifact_brief_with_runtime(runtime, title, intent, request, refinement).await
}

pub fn build_chat_artifact_brief_prompt(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
) -> Result<serde_json::Value, String> {
    build_chat_artifact_brief_prompt_for_runtime(
        title,
        intent,
        request,
        refinement,
        ChatRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

fn chat_artifact_brief_request_focus(request: &ChatOutcomeArtifactRequest) -> serde_json::Value {
    json!({
        "artifactClass": request.artifact_class,
        "deliverableShape": request.deliverable_shape,
        "renderer": request.renderer,
        "presentationSurface": request.presentation_surface,
        "persistence": request.persistence,
        "executionSubstrate": request.execution_substrate,
        "verification": {
            "requireRender": request.verification.require_render,
            "requireExport": request.verification.require_export,
        },
    })
}

pub(crate) fn build_chat_artifact_brief_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_brief_prompt(request.renderer, runtime_kind);
    let request_json = serde_json::to_string(request)
        .map_err(|error| format!("Failed to serialize Chat artifact request: {error}"))?;
    let refinement_json = serde_json::to_string(&chat_artifact_refinement_context_view(refinement))
        .map_err(|error| format!("Failed to serialize Chat refinement context: {error}"))?;
    if compact_prompt {
        let request_focus_json = serde_json::to_string(&chat_artifact_brief_request_focus(request))
            .map_err(|error| format!("Failed to serialize Chat artifact request focus: {error}"))?;
        let continuity_rule = if refinement.is_some() {
            "Preserve stable concepts, interactions, and structure from the current artifact context when they still fit the request."
        } else {
            "No current artifact context is available, so derive the brief directly from the request."
        };
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Chat's typed artifact brief planner. Return exactly one request-grounded artifact brief JSON object. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus JSON:\n{}\n\nCurrent artifact context JSON:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\"audience\":<string>,\"jobToBeDone\":<string>,\"subjectDomain\":<string>,\"artifactThesis\":<string>,\"requiredConcepts\":[<string>],\"requiredInteractions\":[<string>],\"visualTone\":[<string>],\"factualAnchors\":[<string>],\"styleDirectives\":[<string>],\"referenceHints\":[<string>]}}\nRules:\n1) audience, jobToBeDone, subjectDomain, and artifactThesis must be non-empty request-grounded strings.\n2) Preserve the differentiating nouns and framing words from the request.\n3) For html_iframe, requiredConcepts must include at least three concrete request-grounded concepts.\n4) For html_iframe, requiredInteractions must include at least two concrete multi-word on-page interactions with visible response.\n5) Provide at least one factualAnchors or referenceHints entry tied to visible evidence.\n6) For html_iframe, visualTone or styleDirectives must include at least one concrete multi-word design direction that can actually steer composition, not only generic words like clean, interactive, or minimalist.\n7) When the request leaves visual style open, use referenceHints or styleDirectives to name concrete visual devices, metaphors, or diagram families the artifact can stage.\n8) {}\n9) Use empty arrays instead of filler or generic synonyms.",
                    title,
                    intent,
                    request_focus_json,
                    refinement_json,
                    continuity_rule,
                )
            }
        ]));
    }
    let renderer_guidance = chat_artifact_brief_planning_guidance(request);
    let validation_contract = chat_artifact_brief_validation_contract(request);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Chat's typed artifact brief planner. Convert a request into a renderer-agnostic artifact brief before file generation begins. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nCurrent artifact context:\n{}\n\nRenderer-aware brief guidance:\n{}\n\nValidation contract:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"audience\": <string>,\n  \"jobToBeDone\": <string>,\n  \"subjectDomain\": <string>,\n  \"artifactThesis\": <string>,\n  \"requiredConcepts\": [<string>],\n  \"requiredInteractions\": [<string>],\n  \"visualTone\": [<string>],\n  \"factualAnchors\": [<string>],\n  \"styleDirectives\": [<string>],\n  \"referenceHints\": [<string>]\n}}\nRules:\n1) Keep the brief request-grounded, not renderer-template-grounded.\n2) Distinguish subject matter from presentation tone.\n3) Preserve the concrete differentiating nouns and framing words from the request instead of abstracting them away.\n4) audience, jobToBeDone, subjectDomain, and artifactThesis must be non-empty request-grounded strings.\n5) requiredConcepts must include the request-specific concepts that would make a nearby but wrong artifact fail, such as launch/editorial/domain nouns when they matter.\n6) If a refinement context exists, preserve useful continuity and call out what must remain stable.\n7) Use empty arrays instead of invented filler.",
                title,
                intent,
                request_json,
                refinement_json,
                renderer_guidance,
                validation_contract,
            )
        }
    ]))
}

pub(super) fn parse_chat_json_object_value(
    raw: &str,
    missing_payload_error: &str,
    parse_error_prefix: &str,
) -> Result<serde_json::Value, String> {
    let value = serde_json::from_str::<serde_json::Value>(raw).or_else(|_| {
        let extracted = super::extract_first_json_object(raw)
            .ok_or_else(|| missing_payload_error.to_string())?;
        serde_json::from_str::<serde_json::Value>(&extracted).map_err(|error| error.to_string())
    });
    let value = value.map_err(|error| format!("{parse_error_prefix}: {error}"))?;
    if !value.is_object() {
        return Err(format!(
            "{parse_error_prefix}: output must be a JSON object."
        ));
    }
    Ok(value)
}

fn coerce_string_field(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::String(_) => {}
        serde_json::Value::Array(items) => {
            let joined = items
                .iter()
                .filter_map(serde_json::Value::as_str)
                .collect::<Vec<_>>()
                .join(", ");
            *value = serde_json::Value::String(joined);
        }
        serde_json::Value::Null => {
            *value = serde_json::Value::String(String::new());
        }
        _ => {}
    }
}

fn coerce_bool_field(value: &mut serde_json::Value) {
    if let serde_json::Value::String(text) = value {
        let normalized = text.trim().to_ascii_lowercase();
        if normalized == "true" {
            *value = serde_json::Value::Bool(true);
        } else if normalized == "false" {
            *value = serde_json::Value::Bool(false);
        }
    }
}

fn coerce_string_array_field(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(_) => {}
        serde_json::Value::String(text) => {
            let entry = text.trim().to_string();
            *value = if entry.is_empty() {
                serde_json::Value::Array(Vec::new())
            } else {
                serde_json::Value::Array(vec![serde_json::Value::String(entry)])
            };
        }
        serde_json::Value::Null => {
            *value = serde_json::Value::Array(Vec::new());
        }
        _ => {}
    }
}

fn coerce_object_array_field(value: &mut serde_json::Value) {
    match value {
        serde_json::Value::Array(_) => {}
        serde_json::Value::Object(object) => {
            *value = serde_json::Value::Array(vec![serde_json::Value::Object(object.clone())]);
        }
        serde_json::Value::Null => {
            *value = serde_json::Value::Array(Vec::new());
        }
        _ => {}
    }
}

fn normalize_chat_artifact_brief_value(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };

    for field in ["audience", "jobToBeDone", "subjectDomain", "artifactThesis"] {
        if let Some(entry) = object.get_mut(field) {
            coerce_string_field(entry);
        }
    }
    for field in [
        "requiredConcepts",
        "requiredInteractions",
        "visualTone",
        "factualAnchors",
        "styleDirectives",
        "referenceHints",
    ] {
        if let Some(entry) = object.get_mut(field) {
            coerce_string_array_field(entry);
        }
    }
}

fn normalize_chat_outcome_artifact_request_value(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };
    let renderer_defaults = object
        .get("renderer")
        .and_then(serde_json::Value::as_str)
        .and_then(outcome_artifact_renderer_defaults);

    if let Some(defaults) = renderer_defaults {
        for (field, default) in [
            ("artifactClass", defaults.artifact_class),
            ("deliverableShape", defaults.deliverable_shape),
            ("presentationSurface", defaults.presentation_surface),
            ("persistence", defaults.persistence),
            ("executionSubstrate", defaults.execution_substrate),
        ] {
            object
                .entry(field.to_string())
                .or_insert_with(|| serde_json::Value::String(default.to_string()));
        }
    }
    if !object.contains_key("workspaceRecipeId") {
        object.insert("workspaceRecipeId".to_string(), serde_json::Value::Null);
    }
    if !object.contains_key("presentationVariantId") {
        object.insert("presentationVariantId".to_string(), serde_json::Value::Null);
    }

    let scope = object.entry("scope").or_insert_with(|| {
        json!({
            "targetProject": null,
            "createNewWorkspace": false,
            "mutationBoundary": []
        })
    });
    if scope.is_null() {
        *scope = json!({
            "targetProject": null,
            "createNewWorkspace": false,
            "mutationBoundary": []
        });
    }
    if let Some(scope_object) = scope.as_object_mut() {
        if !scope_object.contains_key("targetProject") {
            scope_object.insert("targetProject".to_string(), serde_json::Value::Null);
        }
        if let Some(entry) = scope_object.get_mut("createNewWorkspace") {
            coerce_bool_field(entry);
        } else {
            scope_object.insert(
                "createNewWorkspace".to_string(),
                serde_json::Value::Bool(false),
            );
        }
        if let Some(entry) = scope_object.get_mut("mutationBoundary") {
            coerce_string_array_field(entry);
        } else {
            scope_object.insert(
                "mutationBoundary".to_string(),
                serde_json::Value::Array(Vec::new()),
            );
        }
    }

    let verification = object.entry("verification").or_insert_with(|| {
        json!({
            "requireRender": false,
            "requireBuild": false,
            "requirePreview": false,
            "requireExport": false,
            "requireDiffReview": false
        })
    });
    if verification.is_null() {
        *verification = json!({
            "requireRender": false,
            "requireBuild": false,
            "requirePreview": false,
            "requireExport": false,
            "requireDiffReview": false
        });
    }
    if let Some(verification_object) = verification.as_object_mut() {
        for field in [
            "requireRender",
            "requireBuild",
            "requirePreview",
            "requireExport",
            "requireDiffReview",
        ] {
            if let Some(entry) = verification_object.get_mut(field) {
                coerce_bool_field(entry);
            } else {
                verification_object.insert(field.to_string(), serde_json::Value::Bool(false));
            }
        }
    }
}

pub(super) fn normalize_chat_outcome_planning_value(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };

    if let Some(entry) = object.get_mut("needsClarification") {
        coerce_bool_field(entry);
    }
    if let Some(entry) = object.get_mut("clarificationQuestions") {
        coerce_string_array_field(entry);
    }
    if let Some(entry) = object.get_mut("executionStrategy") {
        if let Some(text) = entry.as_str() {
            *entry = serde_json::Value::String(text.trim().to_ascii_lowercase().replace('-', "_"));
        }
    }
    if let Some(artifact) = object.get_mut("artifact") {
        normalize_chat_outcome_artifact_request_value(artifact);
    }
}

pub(super) fn normalize_inline_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn parse_chat_artifact_brief_lenient(raw: &str) -> Result<ChatArtifactBrief, String> {
    let mut value = parse_chat_json_object_value(
        raw,
        "Chat artifact brief output missing JSON payload",
        "Failed to parse Chat artifact brief",
    )?;
    normalize_chat_artifact_brief_value(&mut value);
    serde_json::from_value::<ChatArtifactBrief>(value)
        .map_err(|error| format!("Failed to parse Chat artifact brief: {error}"))
}

fn trim_sentence_terminal(value: &str) -> String {
    value
        .trim()
        .trim_end_matches(|ch: char| matches!(ch, '.' | ':' | ';'))
        .trim()
        .to_string()
}

fn trim_leading_article(value: &str) -> String {
    let trimmed = trim_sentence_terminal(value);
    let lowered = trimmed.to_ascii_lowercase();
    for prefix in ["a ", "an ", "the "] {
        if lowered.starts_with(prefix) {
            return trimmed[prefix.len()..].trim().to_string();
        }
    }
    trimmed
}

fn title_is_too_generic_for_subject_domain(title: &str) -> bool {
    if title.contains("...") && starts_with_request_directive(title) {
        return true;
    }
    if starts_with_request_directive(title) {
        return true;
    }
    let generic_terms = [
        "artifact",
        "artifacts",
        "bundle",
        "bundles",
        "card",
        "checklist",
        "document",
        "download",
        "downloads",
        "file",
        "files",
        "launch",
        "page",
        "report",
    ];
    let terms = title
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .map(|term| term.to_ascii_lowercase())
        .collect::<Vec<_>>();
    !terms.is_empty()
        && terms
            .iter()
            .all(|term| generic_terms.iter().any(|candidate| candidate == term))
}

fn derive_brief_subject_domain(
    brief: &ChatArtifactBrief,
    title: &str,
    intent: &str,
) -> Option<String> {
    if let Some(intent_candidate) = request_subject_candidate_from_intent(intent) {
        return Some(intent_candidate);
    }

    let title_candidate = trim_sentence_terminal(title);
    if !title_candidate.is_empty() && !title_is_too_generic_for_subject_domain(&title_candidate) {
        return Some(title_candidate);
    }

    let thesis_candidate = trim_leading_article(&brief.artifact_thesis);
    if !thesis_candidate.is_empty() {
        return Some(thesis_candidate);
    }

    if !brief.required_concepts.is_empty() {
        let concepts = brief
            .required_concepts
            .iter()
            .map(|concept| trim_sentence_terminal(concept))
            .filter(|concept| !concept.is_empty())
            .take(2)
            .collect::<Vec<_>>();
        if !concepts.is_empty() {
            return Some(match concepts.as_slice() {
                [only] => only.clone(),
                [first, second] => format!("{first} and {second}"),
                _ => concepts.join(", "),
            });
        }
    }

    let intent_candidate = trim_sentence_terminal(intent);
    if intent_candidate.is_empty() {
        None
    } else {
        Some(intent_candidate)
    }
}

fn derive_brief_audience(
    request: &ChatOutcomeArtifactRequest,
    subject_domain: &str,
) -> Option<String> {
    if subject_domain.trim().is_empty() {
        return None;
    }

    let prefix = match request.renderer {
        ChatRendererKind::Markdown | ChatRendererKind::PdfEmbed => "people reviewing the",
        ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest => {
            "people downloading the"
        }
        ChatRendererKind::HtmlIframe
        | ChatRendererKind::JsxSandbox
        | ChatRendererKind::Svg
        | ChatRendererKind::Mermaid => "people exploring the",
        ChatRendererKind::WorkspaceSurface => "people implementing the",
    };
    Some(format!("{prefix} {subject_domain}"))
}

fn derive_brief_artifact_thesis(
    request: &ChatOutcomeArtifactRequest,
    subject_domain: &str,
) -> Option<String> {
    if subject_domain.trim().is_empty() {
        return None;
    }

    let thesis = match request.renderer {
        ChatRendererKind::Markdown | ChatRendererKind::PdfEmbed => {
            format!("A {subject_domain} document")
        }
        ChatRendererKind::DownloadCard | ChatRendererKind::BundleManifest => {
            format!("A downloadable {subject_domain} bundle")
        }
        ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox => {
            format!("An interactive {subject_domain} artifact")
        }
        ChatRendererKind::Svg | ChatRendererKind::Mermaid => {
            format!("A {subject_domain} visual artifact")
        }
        ChatRendererKind::WorkspaceSurface => {
            format!("A workspace implementation for {subject_domain}")
        }
    };
    Some(thesis)
}

fn salvage_chat_artifact_brief_core_fields(
    raw: &str,
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
) -> Result<ChatArtifactBrief, String> {
    let mut brief = parse_chat_artifact_brief_lenient(raw)?;
    let subject_domain = derive_brief_subject_domain(&brief, title, intent).unwrap_or_default();
    if brief.subject_domain.trim().is_empty() {
        brief.subject_domain = subject_domain.clone();
    }
    if brief.job_to_be_done.trim().is_empty() {
        brief.job_to_be_done = trim_sentence_terminal(intent);
    }
    if brief.audience.trim().is_empty() {
        brief.audience = derive_brief_audience(request, &brief.subject_domain).unwrap_or_default();
    }
    if brief.artifact_thesis.trim().is_empty() {
        brief.artifact_thesis =
            derive_brief_artifact_thesis(request, &brief.subject_domain).unwrap_or_default();
    }
    if brief.required_concepts.is_empty() && !brief.subject_domain.trim().is_empty() {
        brief.required_concepts = vec![brief.subject_domain.clone()];
    }

    Ok(canonicalize_chat_artifact_brief_for_request(brief, request))
}

fn split_interaction_identifier_terms(value: &str) -> Vec<String> {
    let mut terms = Vec::<String>::new();
    let mut current = String::new();
    let mut previous_was_lower_or_digit = false;

    for character in value.chars() {
        if !character.is_alphanumeric() {
            if !current.is_empty() {
                terms.push(std::mem::take(&mut current));
            }
            previous_was_lower_or_digit = false;
            continue;
        }

        if character.is_ascii_uppercase() && previous_was_lower_or_digit && !current.is_empty() {
            terms.push(std::mem::take(&mut current));
        }

        current.push(character.to_ascii_lowercase());
        previous_was_lower_or_digit = character.is_ascii_lowercase() || character.is_ascii_digit();
    }

    if !current.is_empty() {
        terms.push(current);
    }

    terms
}

fn canonical_interaction_response_clause(terms: &[String]) -> &'static str {
    if chat_modal_first_html_enabled() {
        if terms
            .iter()
            .any(|term| matches!(term.as_str(), "hover" | "rollover" | "focus"))
        {
            return "to reveal deeper context inline";
        } else if terms.iter().any(|term| {
            matches!(
                term.as_str(),
                "click" | "switch" | "toggle" | "tab" | "navigation" | "navigate" | "jump" | "view"
            )
        }) {
            return "to switch between authored states or scenes";
        } else if terms
            .iter()
            .any(|term| matches!(term.as_str(), "compare" | "comparison"))
        {
            return "to compare grounded scenarios inline";
        } else {
            return "to make the explanation visibly change on interaction";
        }
    }
    if terms
        .iter()
        .any(|term| matches!(term.as_str(), "hover" | "rollover" | "focus"))
    {
        "to reveal shared detail in the visible detail panel"
    } else if terms.iter().any(|term| {
        matches!(
            term.as_str(),
            "click" | "switch" | "toggle" | "tab" | "navigation" | "navigate" | "jump" | "view"
        )
    }) {
        "to switch the visible evidence view"
    } else if terms
        .iter()
        .any(|term| matches!(term.as_str(), "compare" | "comparison"))
    {
        "to update the shared comparison panel"
    } else {
        "to update the visible chart and detail panel"
    }
}

fn canonicalize_identifier_interaction(value: &str) -> String {
    let normalized = normalize_inline_whitespace(value);
    if normalized.contains(' ') {
        return normalized;
    }

    let terms = split_interaction_identifier_terms(&normalized);
    if terms.len() < 2 {
        return normalized;
    }

    let phrase = terms.join(" ");
    if phrase.contains("update ")
        || phrase.contains("reveal ")
        || phrase.contains("show ")
        || phrase.contains("switch ")
    {
        phrase
    } else {
        format!("{phrase} {}", canonical_interaction_response_clause(&terms))
    }
}

fn canonicalize_brief_list(entries: Vec<String>) -> Vec<String> {
    let mut normalized = Vec::<String>::new();
    for entry in entries {
        let entry = normalize_inline_whitespace(&entry);
        if entry.is_empty()
            || normalized
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&entry))
        {
            continue;
        }
        normalized.push(entry);
    }
    normalized
}

fn canonicalize_brief_interactions(
    interactions: Vec<String>,
    request: &ChatOutcomeArtifactRequest,
) -> Vec<String> {
    let requires_concrete_interactions = matches!(
        request.renderer,
        ChatRendererKind::HtmlIframe | ChatRendererKind::JsxSandbox
    );
    let mut normalized = Vec::<String>::new();

    for interaction in interactions {
        let entry = if requires_concrete_interactions {
            canonicalize_identifier_interaction(&interaction)
        } else {
            normalize_inline_whitespace(&interaction)
        };

        if entry.is_empty()
            || normalized
                .iter()
                .any(|existing| existing.eq_ignore_ascii_case(&entry))
        {
            continue;
        }
        normalized.push(entry);
    }

    normalized
}

fn canonicalize_query_profile_summary(summary: &str) -> Option<String> {
    let normalized = normalize_inline_whitespace(summary);
    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

fn canonicalize_query_profile(mut profile: ChatArtifactQueryProfile) -> ChatArtifactQueryProfile {
    profile.content_goals.retain_mut(|goal| {
        canonicalize_query_profile_summary(&goal.summary)
            .map(|summary| {
                goal.summary = summary;
                true
            })
            .unwrap_or(false)
    });
    profile.interaction_goals.retain_mut(|goal| {
        canonicalize_query_profile_summary(&goal.summary)
            .map(|summary| {
                goal.summary = summary;
                true
            })
            .unwrap_or(false)
    });
    profile.evidence_goals.retain_mut(|goal| {
        canonicalize_query_profile_summary(&goal.summary)
            .map(|summary| {
                goal.summary = summary;
                true
            })
            .unwrap_or(false)
    });
    profile.presentation_constraints.retain_mut(|constraint| {
        canonicalize_query_profile_summary(&constraint.summary)
            .map(|summary| {
                constraint.summary = summary;
                true
            })
            .unwrap_or(false)
    });
    profile
}

pub(super) fn interaction_family_for_kind(kind: ChatArtifactInteractionGoalKind) -> &'static str {
    match kind {
        ChatArtifactInteractionGoalKind::StateSwitch => "view_switching",
        ChatArtifactInteractionGoalKind::DetailInspect => "detail_inspection",
        ChatArtifactInteractionGoalKind::SequenceBrowse => "sequence_browsing",
        ChatArtifactInteractionGoalKind::StateAdjust => "state_manipulation",
        ChatArtifactInteractionGoalKind::GuidedResponse => "guided_response",
    }
}

pub(super) fn brief_interaction_goals(
    brief: &ChatArtifactBrief,
) -> Vec<ChatArtifactInteractionGoal> {
    if let Some(profile) = brief.query_profile.as_ref() {
        return profile
            .interaction_goals
            .iter()
            .filter(|goal| goal.required)
            .cloned()
            .collect();
    }

    brief
        .required_interactions
        .iter()
        .map(|summary| ChatArtifactInteractionGoal {
            kind: ChatArtifactInteractionGoalKind::GuidedResponse,
            summary: summary.clone(),
            required: true,
        })
        .collect()
}

pub(super) fn brief_required_interaction_summaries(brief: &ChatArtifactBrief) -> Vec<String> {
    brief.required_interaction_summaries()
}

pub(super) fn brief_interaction_families(brief: &ChatArtifactBrief) -> Vec<&'static str> {
    let mut families = Vec::<&'static str>::new();
    for goal in brief_interaction_goals(brief) {
        let family = interaction_family_for_kind(goal.kind);
        if !families.contains(&family) {
            families.push(family);
        }
    }
    families
}

pub(crate) fn canonicalize_chat_artifact_brief_for_request(
    mut brief: ChatArtifactBrief,
    request: &ChatOutcomeArtifactRequest,
) -> ChatArtifactBrief {
    brief.audience = normalize_inline_whitespace(&brief.audience);
    brief.job_to_be_done = normalize_inline_whitespace(&brief.job_to_be_done);
    brief.subject_domain = normalize_inline_whitespace(&brief.subject_domain);
    brief.artifact_thesis = normalize_inline_whitespace(&brief.artifact_thesis);
    brief.required_concepts = canonicalize_brief_list(brief.required_concepts);
    brief.visual_tone = canonicalize_brief_list(brief.visual_tone);
    brief.factual_anchors = canonicalize_brief_list(brief.factual_anchors);
    brief.style_directives = canonicalize_brief_list(brief.style_directives);
    brief.reference_hints = canonicalize_brief_list(brief.reference_hints);
    brief.required_interactions =
        canonicalize_brief_interactions(std::mem::take(&mut brief.required_interactions), request);
    let query_profile = brief
        .query_profile
        .take()
        .map(canonicalize_query_profile)
        .unwrap_or_else(|| request_grounded_query_profile(request, &brief.subject_domain));
    if brief.required_interactions.is_empty() {
        brief.required_interactions =
            request_grounded_required_interactions(request, &brief.subject_domain, &query_profile);
    }
    brief.query_profile = Some(query_profile);
    brief
}

fn normalize_chat_artifact_edit_intent_value(value: &mut serde_json::Value) {
    let Some(object) = value.as_object_mut() else {
        return;
    };

    for field in ["mode", "summary", "targetScope"] {
        if let Some(entry) = object.get_mut(field) {
            coerce_string_field(entry);
        }
    }
    for field in [
        "patchExistingArtifact",
        "preserveStructure",
        "branchRequested",
    ] {
        if let Some(entry) = object.get_mut(field) {
            coerce_bool_field(entry);
        }
    }
    for field in [
        "targetPaths",
        "requestedOperations",
        "toneDirectives",
        "styleDirectives",
    ] {
        if let Some(entry) = object.get_mut(field) {
            coerce_string_array_field(entry);
        }
    }
    if let Some(entry) = object.get_mut("selectedTargets") {
        coerce_object_array_field(entry);
    }
}

pub fn parse_chat_artifact_brief(raw: &str) -> Result<ChatArtifactBrief, String> {
    let mut value = parse_chat_json_object_value(
        raw,
        "Chat artifact brief output missing JSON payload",
        "Failed to parse Chat artifact brief",
    )?;
    normalize_chat_artifact_brief_value(&mut value);
    let brief = serde_json::from_value::<ChatArtifactBrief>(value)
        .map_err(|error| format!("Failed to parse Chat artifact brief: {error}"))?;

    if brief.audience.trim().is_empty()
        || brief.job_to_be_done.trim().is_empty()
        || brief.subject_domain.trim().is_empty()
        || brief.artifact_thesis.trim().is_empty()
    {
        return Err("Chat artifact brief fields must not be empty.".to_string());
    }

    Ok(brief)
}

fn chat_artifact_brief_planning_guidance(request: &ChatOutcomeArtifactRequest) -> String {
    match request.renderer {
        ChatRendererKind::HtmlIframe => {
            if request.artifact_class == ChatArtifactClass::InteractiveSingleFile {
                "- Name at least two concrete on-page interaction patterns in requiredInteractions.\n- Single-word labels like \"interactive\" or \"explains\" are not sufficient interaction plans.\n- Keep requiredConcepts tied to the visible evidence surfaces or sections.\n- Provide at least one concrete evidence anchor or reference hint.\n- Give visualTone or styleDirectives at least one multi-word design direction that a materializer can actually stage, not just generic words like clean, modern, or interactive.".to_string()
            } else {
                "- Keep requiredConcepts tied to the visible evidence surfaces or sections.\n- Do not invent interaction requirements that the request did not ask for.\n- Provide at least one concrete evidence anchor or reference hint.\n- Give visualTone or styleDirectives at least one multi-word design direction that a materializer can actually stage, not just generic words like clean or modern.".to_string()
            }
        }
        ChatRendererKind::JsxSandbox => "- Name at least one concrete stateful interaction.\n- requiredInteractions should describe user action plus visible response.".to_string(),
        _ => "- Keep the brief concrete, request-specific, and directly usable by the materializer.".to_string(),
    }
}

fn chat_artifact_brief_validation_contract(request: &ChatOutcomeArtifactRequest) -> String {
    match request.renderer {
        ChatRendererKind::HtmlIframe => {
            if request.artifact_class == ChatArtifactClass::InteractiveSingleFile {
                "- requiredConcepts must include at least three concrete request-grounded concepts.\n- requiredInteractions must include at least two multi-word interaction descriptions.\n- At least one factualAnchors or referenceHints entry must be present.\n- visualTone or styleDirectives must contribute at least one concrete multi-word design direction instead of only generic style adjectives.".to_string()
            } else {
                "- requiredConcepts must include at least three concrete request-grounded concepts.\n- requiredInteractions may be empty for non-interactive HTML documents.\n- At least one factualAnchors or referenceHints entry must be present.\n- visualTone or styleDirectives must contribute at least one concrete multi-word design direction instead of only generic style adjectives.".to_string()
            }
        }
        ChatRendererKind::JsxSandbox => {
            "- requiredInteractions must include at least one multi-word interaction description."
                .to_string()
        }
        _ => "- Keep required fields non-empty and list fields schema-valid.".to_string(),
    }
}

fn interaction_phrase_term_count(value: &str) -> usize {
    value
        .split(|ch: char| !ch.is_alphanumeric())
        .filter(|term| !term.is_empty())
        .count()
}

fn interaction_grounding_noise_term(term: &str) -> bool {
    matches!(
        term,
        "a" | "an"
            | "and"
            | "artifact"
            | "artifacts"
            | "experience"
            | "for"
            | "from"
            | "in"
            | "interactive"
            | "interaction"
            | "interactions"
            | "of"
            | "on"
            | "page"
            | "pages"
            | "surface"
            | "surfaces"
            | "the"
            | "to"
            | "ui"
            | "ux"
            | "with"
    )
}

fn interaction_behavior_term(term: &str) -> bool {
    [
        "browse",
        "click",
        "compare",
        "detail",
        "drill",
        "filter",
        "focus",
        "highlight",
        "hover",
        "inspect",
        "nav",
        "rollover",
        "scrub",
        "scroll",
        "select",
        "sequence",
        "step",
        "switch",
        "tab",
        "toggle",
        "view",
    ]
    .iter()
    .any(|prefix| term.starts_with(prefix))
}

fn interaction_grounding_terms(brief: &ChatArtifactBrief) -> Vec<String> {
    let mut terms = Vec::<String>::new();
    for value in std::iter::once(brief.subject_domain.as_str())
        .chain(std::iter::once(brief.artifact_thesis.as_str()))
        .chain(brief.required_concepts.iter().map(String::as_str))
        .chain(brief.factual_anchors.iter().map(String::as_str))
        .chain(brief.reference_hints.iter().map(String::as_str))
    {
        for term in split_interaction_identifier_terms(value) {
            if term.len() < 3
                || interaction_grounding_noise_term(&term)
                || terms.iter().any(|existing| existing == &term)
            {
                continue;
            }
            terms.push(term);
        }
    }
    terms
}

fn refinement_interaction_grounding_terms(
    refinement: &ChatArtifactRefinementContext,
) -> Vec<String> {
    let mut terms = Vec::<String>::new();
    for value in std::iter::once(refinement.title.as_str())
        .chain(std::iter::once(refinement.summary.as_str()))
        .chain(refinement.files.iter().map(|file| file.path.as_str()))
        .chain(refinement.files.iter().map(|file| file.body.as_str()))
        .chain(
            refinement
                .selected_targets
                .iter()
                .map(|target| target.label.as_str()),
        )
        .chain(
            refinement
                .selected_targets
                .iter()
                .map(|target| target.snippet.as_str()),
        )
    {
        for term in split_interaction_identifier_terms(value) {
            if term.len() < 3
                || interaction_grounding_noise_term(&term)
                || terms.iter().any(|existing| existing == &term)
            {
                continue;
            }
            terms.push(term);
        }
    }
    terms
}

fn interaction_grounding_terms_for_validation(
    brief: &ChatArtifactBrief,
    refinement: Option<&ChatArtifactRefinementContext>,
) -> Vec<String> {
    let mut terms = interaction_grounding_terms(brief);
    if let Some(refinement) = refinement {
        for term in refinement_interaction_grounding_terms(refinement) {
            if !terms.iter().any(|existing| existing == &term) {
                terms.push(term);
            }
        }
    }
    terms
}

fn interaction_has_grounded_terms(interaction: &str, grounding_terms: &[String]) -> bool {
    let terms = split_interaction_identifier_terms(interaction)
        .into_iter()
        .filter(|term| term.len() >= 3 && !interaction_grounding_noise_term(term))
        .collect::<Vec<_>>();
    if terms.is_empty() {
        return false;
    }

    terms.iter().any(|term| {
        interaction_behavior_term(term) || grounding_terms.iter().any(|grounding| grounding == term)
    })
}

fn html_visual_direction_noise_term(term: &str) -> bool {
    matches!(
        term,
        "a" | "an"
            | "and"
            | "clean"
            | "cool"
            | "educational"
            | "friendly"
            | "interactive"
            | "minimal"
            | "minimalist"
            | "modern"
            | "of"
            | "polished"
            | "professional"
            | "simple"
            | "sleek"
            | "the"
            | "usable"
            | "visual"
    )
}

fn html_visual_direction_entry_is_specific(entry: &str) -> bool {
    let terms = split_interaction_identifier_terms(entry)
        .into_iter()
        .filter(|term| term.len() >= 3)
        .collect::<Vec<_>>();
    if terms.len() < 2 {
        return false;
    }

    terms
        .iter()
        .any(|term| !html_visual_direction_noise_term(term))
}

fn brief_has_specific_html_visual_direction(brief: &ChatArtifactBrief) -> bool {
    brief
        .visual_tone
        .iter()
        .chain(brief.style_directives.iter())
        .any(|entry| html_visual_direction_entry_is_specific(entry))
}

pub fn build_chat_artifact_exemplar_query(
    brief: &ChatArtifactBrief,
    blueprint: &ChatArtifactBlueprint,
    artifact_ir: &ChatArtifactIR,
    taste_memory: Option<&ChatArtifactTasteMemory>,
) -> String {
    let section_roles = blueprint
        .section_plan
        .iter()
        .map(|section| section.role.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let interaction_families = blueprint
        .interaction_plan
        .iter()
        .map(|interaction| interaction.family.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let evidence_kinds = blueprint
        .evidence_plan
        .iter()
        .map(|entry| entry.kind.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let component_patterns = blueprint
        .component_plan
        .iter()
        .map(|component| component.component_family.clone())
        .collect::<Vec<_>>()
        .join(", ");
    let typography_preferences = taste_memory
        .map(|memory| memory.typography_preferences.join(", "))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| blueprint.design_system.typography_strategy.clone());
    let density_preference = taste_memory
        .and_then(|memory| memory.density_preference.clone())
        .unwrap_or_else(|| blueprint.design_system.density.clone());
    let tone_family = taste_memory
        .map(|memory| memory.tone_family.join(", "))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| brief.visual_tone.join(", "));
    let motion_tolerance = taste_memory
        .and_then(|memory| memory.motion_tolerance.clone())
        .unwrap_or_else(|| blueprint.design_system.motion_style.clone());
    let preferred_scaffolds = taste_memory
        .map(|memory| memory.preferred_scaffold_families.join(", "))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| blueprint.scaffold_family.clone());
    let preferred_components = taste_memory
        .map(|memory| memory.preferred_component_patterns.join(", "))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| component_patterns.clone());
    let anti_patterns = taste_memory
        .map(|memory| memory.anti_patterns.join(", "))
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "none noted".to_string());

    let required_interactions = brief_required_interaction_summaries(brief).join(", ");

    format!(
        "Chat artifact exemplar retrieval.\nRenderer: {:?}\nScaffold family: {}\nAudience: {}\nJob to be done: {}\nSubject domain: {}\nArtifact thesis: {}\nSection roles: {}\nInteraction families: {}\nEvidence kinds: {}\nComponent patterns: {}\nRequired concepts: {}\nRequired interactions: {}\nTypography preferences: {}\nDensity preference: {}\nTone family: {}\nMotion tolerance: {}\nPreferred scaffold families: {}\nPreferred component patterns: {}\nAnti patterns: {}\nStatic audit expectations: {}\nRender evaluation checklist: {}\nRetrieve high-quality prior artifacts that match this structural shape and design intent. Use them as structural grounding only, never as text-copy templates.",
        blueprint.renderer,
        blueprint.scaffold_family,
        brief.audience,
        brief.job_to_be_done,
        brief.subject_domain,
        brief.artifact_thesis,
        section_roles,
        interaction_families,
        evidence_kinds,
        component_patterns,
        brief.required_concepts.join(", "),
        required_interactions,
        typography_preferences,
        density_preference,
        tone_family,
        motion_tolerance,
        preferred_scaffolds,
        preferred_components,
        anti_patterns,
        artifact_ir.static_audit_expectations.join(", "),
        artifact_ir.render_eval_checklist.join(", "),
    )
}

pub(crate) fn validate_chat_artifact_brief_against_request(
    brief: &ChatArtifactBrief,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
) -> Result<(), String> {
    if brief.required_concepts.is_empty() {
        return Err("Chat artifact briefs must include at least one required concept.".to_string());
    }

    match request.renderer {
        ChatRendererKind::HtmlIframe => {
            if brief.required_concepts.len() < 3 {
                return Err(
                    "HTML briefs must keep at least three concrete request concepts visible."
                        .to_string(),
                );
            }
            if brief.factual_anchors.is_empty() && brief.reference_hints.is_empty() {
                return Err(
                    "HTML briefs must identify at least one concrete evidence anchor or reference hint."
                        .to_string(),
                );
            }
            if !brief_has_specific_html_visual_direction(brief) {
                return Err(
                    "HTML briefs must contribute at least one concrete multi-word visual direction, not only generic tone words."
                        .to_string(),
                );
            }
            if request.artifact_class == ChatArtifactClass::InteractiveSingleFile {
                let required_interactions = brief_required_interaction_summaries(brief);
                if required_interactions.len() < 2 {
                    return Err(
                        "Interactive HTML briefs must name at least two concrete interaction patterns."
                            .to_string(),
                    );
                }
                if required_interactions
                    .iter()
                    .any(|interaction| interaction_phrase_term_count(interaction) < 2)
                {
                    return Err(
                        "Interactive HTML brief interactions must describe concrete user actions and visible on-page responses, not single-word labels."
                            .to_string(),
                    );
                }
                let grounding_terms = interaction_grounding_terms_for_validation(brief, refinement);
                if required_interactions.iter().any(|interaction| {
                    !interaction_has_grounded_terms(interaction, &grounding_terms)
                }) {
                    return Err(
                        "Interactive HTML briefs must keep requiredInteractions grounded in request concepts, evidence anchors, or concrete on-page behavior."
                            .to_string(),
                    );
                }
            }
        }
        ChatRendererKind::JsxSandbox => {
            let required_interactions = brief_required_interaction_summaries(brief);
            if required_interactions.is_empty() {
                return Err(
                    "Interactive JSX briefs must name at least one concrete interaction pattern."
                        .to_string(),
                );
            }
            if required_interactions
                .iter()
                .any(|interaction| interaction_phrase_term_count(interaction) < 2)
            {
                return Err(
                    "Interactive JSX brief interactions must describe concrete user actions and visible component responses."
                        .to_string(),
                );
            }
        }
        _ => {}
    }

    Ok(())
}

pub fn build_chat_artifact_brief_repair_prompt(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    build_chat_artifact_brief_repair_prompt_for_runtime(
        title,
        intent,
        request,
        refinement,
        raw_output,
        failure,
        ChatRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

fn build_chat_artifact_brief_repair_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    raw_output: &str,
    failure: &str,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_brief_prompt(request.renderer, runtime_kind);
    let request_json = serde_json::to_string(request)
        .map_err(|error| format!("Failed to serialize Chat artifact request: {error}"))?;
    let refinement_json = serde_json::to_string(&chat_artifact_refinement_context_view(refinement))
        .map_err(|error| format!("Failed to serialize Chat refinement context: {error}"))?;
    if compact_prompt {
        let request_focus_json = serde_json::to_string(&chat_artifact_brief_request_focus(request))
            .map_err(|error| format!("Failed to serialize Chat artifact request focus: {error}"))?;
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Chat's typed artifact brief repairer. Repair the previous brief into one schema-valid request-grounded artifact brief JSON object. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus JSON:\n{}\n\nCurrent artifact context JSON:\n{}\n\nFailure:\n{}\n\nPrevious raw output excerpt:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\"audience\":<string>,\"jobToBeDone\":<string>,\"subjectDomain\":<string>,\"artifactThesis\":<string>,\"requiredConcepts\":[<string>],\"requiredInteractions\":[<string>],\"visualTone\":[<string>],\"factualAnchors\":[<string>],\"styleDirectives\":[<string>],\"referenceHints\":[<string>]}}\nRules:\n1) Use arrays for every list field, even for one item.\n2) The four core string fields must be non-empty and request-grounded.\n3) Preserve the differentiating nouns and framing words from the request.\n4) For html_iframe, keep at least three concrete concepts, at least two concrete multi-word interactions, and at least one evidence anchor or reference hint.\n5) For html_iframe, supply at least one concrete multi-word visual direction in visualTone or styleDirectives instead of generic style adjectives alone.\n6) Use empty arrays instead of filler.",
                    title,
                    intent,
                    request_focus_json,
                    refinement_json,
                    failure,
                    truncate_planning_preview(raw_output, 1600),
                )
            }
        ]));
    }
    let renderer_guidance = chat_artifact_brief_planning_guidance(request);
    let validation_contract = chat_artifact_brief_validation_contract(request);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Chat's typed artifact brief repairer. Repair the previous brief into a schema-valid renderer-agnostic artifact brief. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nCurrent artifact context:\n{}\n\nRenderer-aware brief guidance:\n{}\n\nValidation contract:\n{}\n\nThe previous brief output was rejected.\nFailure:\n{}\n\nPrevious raw output:\n{}\n\nRepair the brief so it is schema-valid, request-grounded, and preserves the concrete differentiating nouns from the request.\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"audience\": <string>,\n  \"jobToBeDone\": <string>,\n  \"subjectDomain\": <string>,\n  \"artifactThesis\": <string>,\n  \"requiredConcepts\": [<string>],\n  \"requiredInteractions\": [<string>],\n  \"visualTone\": [<string>],\n  \"factualAnchors\": [<string>],\n  \"styleDirectives\": [<string>],\n  \"referenceHints\": [<string>]\n}}\nRules:\n1) Use arrays for every list field, even when there is only one item.\n2) audience, jobToBeDone, subjectDomain, and artifactThesis must be non-empty request-grounded strings.\n3) Keep the brief request-grounded, not renderer-template-grounded.\n4) Use empty arrays instead of invented filler.",
                title,
                intent,
                request_json,
                refinement_json,
                renderer_guidance,
                validation_contract,
                failure,
                raw_output,
            )
        }
    ]))
}

pub fn build_chat_artifact_brief_field_repair_prompt(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    first_raw_output: &str,
    repair_raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    build_chat_artifact_brief_field_repair_prompt_for_runtime(
        title,
        intent,
        request,
        refinement,
        first_raw_output,
        repair_raw_output,
        failure,
        ChatRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

fn build_chat_artifact_brief_field_repair_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    refinement: Option<&ChatArtifactRefinementContext>,
    first_raw_output: &str,
    repair_raw_output: &str,
    failure: &str,
    runtime_kind: ChatRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_brief_prompt(request.renderer, runtime_kind);
    let request_json = serde_json::to_string(request)
        .map_err(|error| format!("Failed to serialize Chat artifact request: {error}"))?;
    let refinement_json = serde_json::to_string(&chat_artifact_refinement_context_view(refinement))
        .map_err(|error| format!("Failed to serialize Chat refinement context: {error}"))?;
    if compact_prompt {
        let request_focus_json = serde_json::to_string(&chat_artifact_brief_request_focus(request))
            .map_err(|error| format!("Failed to serialize Chat artifact request focus: {error}"))?;
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Chat's typed artifact brief field repairer. Replace invalid or empty fields with the shortest request-grounded schema-valid brief JSON object. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus JSON:\n{}\n\nCurrent artifact context JSON:\n{}\n\nFailure:\n{}\n\nPlanner output preview:\n{}\n\nRepair output preview:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\"audience\":<string>,\"jobToBeDone\":<string>,\"subjectDomain\":<string>,\"artifactThesis\":<string>,\"requiredConcepts\":[<string>],\"requiredInteractions\":[<string>],\"visualTone\":[<string>],\"factualAnchors\":[<string>],\"styleDirectives\":[<string>],\"referenceHints\":[<string>]}}\nRules:\n1) Every string field must be non-empty and request-grounded.\n2) Preserve the differentiating subject nouns from the request.\n3) Keep list items short, concrete, and schema-valid arrays.\n4) For html_iframe, keep at least three concepts, at least two multi-word interactions, and at least one evidence anchor or reference hint.\n5) For html_iframe, keep at least one concrete multi-word visual direction in visualTone or styleDirectives.\n6) Do not leave required strings blank.",
                    title,
                    intent,
                    request_focus_json,
                    refinement_json,
                    failure,
                    truncate_planning_preview(first_raw_output, 420),
                    truncate_planning_preview(repair_raw_output, 420),
                )
            }
        ]));
    }
    let renderer_guidance = chat_artifact_brief_planning_guidance(request);
    let validation_contract = chat_artifact_brief_validation_contract(request);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Chat's typed artifact brief field repairer. Replace invalid or empty brief fields with the shortest request-grounded values that satisfy the schema. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nCurrent artifact context:\n{}\n\nRenderer-aware brief guidance:\n{}\n\nValidation contract:\n{}\n\nThe planner and repair pass still failed.\nFailure:\n{}\n\nPlanner output preview:\n{}\n\nRepair output preview:\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"audience\": <string>,\n  \"jobToBeDone\": <string>,\n  \"subjectDomain\": <string>,\n  \"artifactThesis\": <string>,\n  \"requiredConcepts\": [<string>],\n  \"requiredInteractions\": [<string>],\n  \"visualTone\": [<string>],\n  \"factualAnchors\": [<string>],\n  \"styleDirectives\": [<string>],\n  \"referenceHints\": [<string>]\n}}\nRules:\n1) Every string field must be non-empty and request-grounded.\n2) Use arrays for every list field.\n3) Keep list items concrete and short.\n4) Preserve the differentiating subject nouns from the request.\n5) Do not leave required strings blank.",
                title,
                intent,
                request_json,
                refinement_json,
                renderer_guidance,
                validation_contract,
                failure,
                truncate_planning_preview(first_raw_output, 700),
                truncate_planning_preview(repair_raw_output, 700),
            )
        }
    ]))
}

pub async fn plan_chat_artifact_edit_intent_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    refinement: &ChatArtifactRefinementContext,
) -> Result<ChatArtifactEditIntent, String> {
    let runtime_provenance = runtime.chat_runtime_provenance();
    let compact_local_contract =
        runtime_provenance.kind == ChatRuntimeProvenanceKind::RealLocalRuntime;
    let payload = build_chat_artifact_edit_intent_prompt(intent, request, brief, refinement)?;
    let input = serde_json::to_vec(&payload)
        .map_err(|error| format!("Failed to encode Chat artifact edit-intent prompt: {error}"))?;
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: 0.0,
                json_mode: !compact_local_contract,
                max_tokens: 384,
                ..Default::default()
            },
        )
        .await
        .map_err(|error| format!("Chat artifact edit-intent inference failed: {error}"))?;
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Chat artifact edit-intent utf8 decode failed: {error}"))?;
    match parse_chat_artifact_edit_intent(&raw) {
        Ok(edit_intent) => Ok(edit_intent),
        Err(first_error) => {
            let repair_payload = build_chat_artifact_edit_intent_repair_prompt(
                intent,
                request,
                brief,
                refinement,
                &raw,
                &first_error,
            )?;
            let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                format!("Failed to encode Chat artifact edit-intent repair prompt: {error}")
            })?;
            let repair_output = runtime
                .execute_inference(
                    [0u8; 32],
                    &repair_input,
                    InferenceOptions {
                        temperature: 0.0,
                        json_mode: !compact_local_contract,
                        max_tokens: 384,
                        ..Default::default()
                    },
                )
                .await
                .map_err(|error| {
                    format!("{first_error}; edit-intent repair inference failed: {error}")
                })?;
            let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                format!("{first_error}; edit-intent repair utf8 decode failed: {error}")
            })?;
            parse_chat_artifact_edit_intent(&repair_raw).map_err(|repair_error| {
                format!("{first_error}; edit-intent repair attempt also failed: {repair_error}")
            })
        }
    }
}

pub fn build_chat_artifact_edit_intent_prompt(
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    refinement: &ChatArtifactRefinementContext,
) -> Result<serde_json::Value, String> {
    let request_json = serde_json::to_string_pretty(request)
        .map_err(|error| format!("Failed to serialize Chat artifact request: {error}"))?;
    let brief_json = serde_json::to_string_pretty(brief)
        .map_err(|error| format!("Failed to serialize Chat artifact brief: {error}"))?;
    let refinement_json =
        serde_json::to_string_pretty(&chat_artifact_refinement_context_view(Some(refinement)))
            .map_err(|error| format!("Failed to serialize Chat refinement context: {error}"))?;
    let output_contract =
        "Edit-intent output contract:\nReturn the decision inside the exact JSON schema below; do not answer with raw prose, bullet notes, or commentary outside the JSON object.";
    Ok(json!([
        {
            "role": "system",
            "content": "You are Chat's typed artifact edit-intent planner. Decide whether a follow-up should patch, replace, or branch the current artifact. Produce exactly one JSON object. Do not emit prose outside JSON."
        },
        {
            "role": "user",
            "content": format!(
                "Follow-up request:\n{}\n\nArtifact request JSON:\n{}\n\nCurrent brief JSON:\n{}\n\nCurrent artifact context:\n{}\n\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"mode\": \"create\" | \"patch\" | \"replace\" | \"branch\",\n  \"summary\": <string>,\n  \"patchExistingArtifact\": <boolean>,\n  \"preserveStructure\": <boolean>,\n  \"targetScope\": <string>,\n  \"targetPaths\": [<string>],\n  \"requestedOperations\": [<string>],\n  \"toneDirectives\": [<string>],\n  \"selectedTargets\": [{{\n    \"sourceSurface\": <string>,\n    \"path\": null | <string>,\n    \"label\": <string>,\n    \"snippet\": <string>\n  }}],\n  \"styleDirectives\": [<string>],\n  \"branchRequested\": <boolean>\n}}\nRules:\n1) Prefer patchExistingArtifact=true when the request sounds like refinement, not replacement.\n2) Preserve structure when the user explicitly asks to keep structure or continuity.\n3) Selected targets must stay grounded in the supplied context; do not invent paths.\n4) Preserve explicit user steering words in toneDirectives or styleDirectives instead of paraphrasing them into broader synonyms.\n5) If the request says \"more X\", \"less X\", or \"make it feel X\", keep X verbatim in toneDirectives or styleDirectives.",
                intent,
                request_json,
                brief_json,
                refinement_json,
                output_contract,
            )
        }
    ]))
}

pub fn parse_chat_artifact_edit_intent(raw: &str) -> Result<ChatArtifactEditIntent, String> {
    let mut value = parse_chat_json_object_value(
        raw,
        "Chat artifact edit-intent output missing JSON payload",
        "Failed to parse Chat artifact edit intent",
    )?;
    normalize_chat_artifact_edit_intent_value(&mut value);
    let intent = serde_json::from_value::<ChatArtifactEditIntent>(value)
        .map_err(|error| format!("Failed to parse Chat artifact edit intent: {error}"))?;

    if intent.summary.trim().is_empty() || intent.target_scope.trim().is_empty() {
        return Err("Chat artifact edit intent fields must not be empty.".to_string());
    }

    Ok(intent)
}

pub fn build_chat_artifact_edit_intent_repair_prompt(
    intent: &str,
    request: &ChatOutcomeArtifactRequest,
    brief: &ChatArtifactBrief,
    refinement: &ChatArtifactRefinementContext,
    raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    let request_json = serde_json::to_string_pretty(request)
        .map_err(|error| format!("Failed to serialize Chat artifact request: {error}"))?;
    let brief_json = serde_json::to_string_pretty(brief)
        .map_err(|error| format!("Failed to serialize Chat artifact brief: {error}"))?;
    let refinement_json =
        serde_json::to_string_pretty(&chat_artifact_refinement_context_view(Some(refinement)))
            .map_err(|error| format!("Failed to serialize Chat refinement context: {error}"))?;
    let repair_contract = if failure
        .to_ascii_lowercase()
        .contains("missing json payload")
    {
        "Edit-intent repair contract:\nReturn the repaired decision inside the exact JSON schema below; do not answer with raw prose, bullet notes, or commentary outside the JSON object."
    } else {
        "Edit-intent repair contract:\nReturn the repaired decision inside the exact JSON schema below."
    };
    Ok(json!([
        {
            "role": "system",
            "content": "You are Chat's typed artifact edit-intent repairer. Repair the previous edit intent into a schema-valid decision about patch, replace, or branch. Produce exactly one JSON object. Do not emit prose outside JSON."
        },
        {
            "role": "user",
            "content": format!(
                "Follow-up request:\n{}\n\nArtifact request JSON:\n{}\n\nCurrent brief JSON:\n{}\n\nCurrent artifact context:\n{}\n\nThe previous edit intent output was rejected.\nFailure:\n{}\n\nPrevious raw output:\n{}\n\nRepair the edit intent so it is schema-valid, continuity-aware, and grounded in the supplied artifact context.\n\n{}\n\nReturn exactly one JSON object with this camelCase schema:\n{{\n  \"mode\": \"create\" | \"patch\" | \"replace\" | \"branch\",\n  \"summary\": <string>,\n  \"patchExistingArtifact\": <boolean>,\n  \"preserveStructure\": <boolean>,\n  \"targetScope\": <string>,\n  \"targetPaths\": [<string>],\n  \"requestedOperations\": [<string>],\n  \"toneDirectives\": [<string>],\n  \"selectedTargets\": [{{\n    \"sourceSurface\": <string>,\n    \"path\": null | <string>,\n    \"label\": <string>,\n    \"snippet\": <string>\n  }}],\n  \"styleDirectives\": [<string>],\n  \"branchRequested\": <boolean>\n}}\nRules:\n1) Prefer patchExistingArtifact=true when the request sounds like refinement, not replacement.\n2) Use arrays for every list field, even when there is only one item.\n3) Selected targets must stay grounded in the supplied context; do not invent paths.\n4) Preserve explicit user steering words in toneDirectives or styleDirectives instead of paraphrasing them into broader synonyms.\n5) If the request says \"more X\", \"less X\", or \"make it feel X\", keep X verbatim in toneDirectives or styleDirectives.",
                intent,
                request_json,
                brief_json,
                refinement_json,
                failure,
                raw_output,
                repair_contract,
            )
        }
    ]))
}
