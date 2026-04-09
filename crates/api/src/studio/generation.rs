use super::judging::{
    candidate_generation_config, candidate_seed_for, html_first_paint_section_blueprint,
    judge_clears_primary_view, judge_studio_artifact_candidate_with_runtime_and_render_eval,
    judge_total_score, materialization_max_tokens, output_origin_from_provenance,
    refined_candidate_root, renderer_supports_semantic_refinement, runtime_model_label,
    semantic_refinement_pass_limit, studio_artifact_refinement_candidate_view,
    studio_artifact_refinement_context_view, summarized_guidance_terms,
};
use super::*;
use crate::execution::{
    annotate_execution_envelope, build_execution_envelope_from_swarm,
    completion_invariant_for_direct_execution, derive_execution_mode_decision,
    ExecutionCompletionInvariantStatus, ExecutionDomainKind, ExecutionEnvelope,
    ExecutionLivePreview, ExecutionLivePreviewKind,
};
use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::{
    sync::mpsc,
    task::{JoinHandle, JoinSet},
    time::MissedTickBehavior,
};

mod swarm;

use swarm::{
    default_generated_artifact_file_for_renderer, default_studio_artifact_execution_strategy,
    judge_classification_id, push_unique_focus_strings, section_region_id,
    studio_artifact_uses_swarm_execution, studio_swarm_execution_summary, studio_swarm_now_iso,
    studio_swarm_soft_validation_error, studio_swarm_strategy_for_request,
    update_swarm_work_item_status,
};

fn studio_generation_trace(message: impl AsRef<str>) {
    if std::env::var_os("IOI_STUDIO_PROOF_TRACE").is_some() {
        eprintln!("[studio-proof-trace] {}", message.as_ref());
    }
}

#[derive(Debug, Clone)]
pub(super) struct StudioCandidateMaterializationError {
    message: String,
    raw_output_preview: Option<String>,
}

impl From<String> for StudioCandidateMaterializationError {
    fn from(message: String) -> Self {
        Self {
            message,
            raw_output_preview: None,
        }
    }
}

fn truncate_candidate_failure_preview(raw: &str, max_chars: usize) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut preview = trimmed.chars().take(max_chars).collect::<String>();
    if trimmed.chars().count() > max_chars {
        preview.push_str("...");
    }
    Some(preview)
}

fn live_token_stream_preview_text(raw: &str, max_chars: usize) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let chars = trimmed.chars().collect::<Vec<_>>();
    if chars.len() <= max_chars {
        return trimmed.to_string();
    }

    let tail = chars[chars.len().saturating_sub(max_chars)..]
        .iter()
        .collect::<String>();
    format!("[showing latest streamed output]\n{tail}")
}

fn trace_html_contract_state(
    stage: &str,
    request: &StudioOutcomeArtifactRequest,
    candidate_id: &str,
    payload: &StudioGeneratedArtifactPayload,
) {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return;
    }

    let Some(primary_html) = payload.files.iter().find(|file| {
        matches!(
            file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        ) && (file.mime == "text/html" || file.path.ends_with(".html"))
    }) else {
        return;
    };

    let lower = primary_html.body.to_ascii_lowercase();
    studio_generation_trace(format!(
        "{stage} id={} rollover_marks={} detail_regions={} has_rollover_behavior={} unfocusable_rollover={} rollover_chip_rail={} repair_shims={}",
        candidate_id,
        count_html_rollover_detail_marks(&lower),
        count_populated_html_detail_regions(&lower),
        html_contains_rollover_detail_behavior(&lower),
        html_has_unfocusable_rollover_marks(&lower),
        lower.contains("data-studio-rollover-chip-rail=\"true\""),
        count_html_repair_shim_markers(&lower),
    ));
}

fn compact_local_html_materialization_prompt(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> bool {
    renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
}

pub(crate) fn effective_candidate_generation_temperature(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
    configured_temperature: f32,
) -> f32 {
    // Keep local HTML stability policy tied to runtime shape and prompt budget,
    // not to a particular model family label.
    if compact_local_html_materialization_prompt(renderer, runtime_kind) {
        if studio_modal_first_html_enabled() {
            return configured_temperature;
        }
        return configured_temperature.min(0.32);
    }

    configured_temperature
}

fn effective_direct_author_temperature(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
    configured_temperature: f32,
) -> f32 {
    if renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        return configured_temperature.min(0.28);
    }

    effective_candidate_generation_temperature(renderer, runtime_kind, configured_temperature)
}

pub(crate) fn materialization_max_tokens_for_runtime(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> u32 {
    if compact_local_html_materialization_prompt(renderer, runtime_kind) {
        if studio_modal_first_html_enabled() {
            return 4200;
        }
        return 2200;
    }

    materialization_max_tokens(renderer)
}

fn materialization_max_tokens_for_execution_strategy(
    renderer: StudioRendererKind,
    execution_strategy: StudioExecutionStrategy,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> u32 {
    if execution_strategy == StudioExecutionStrategy::DirectAuthor {
        let direct_author_budget = match renderer {
            StudioRendererKind::Markdown | StudioRendererKind::Mermaid => {
                if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                    1200
                } else {
                    materialization_max_tokens(renderer).min(1800)
                }
            }
            StudioRendererKind::Svg | StudioRendererKind::PdfEmbed => {
                if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                    1600
                } else {
                    materialization_max_tokens(renderer).min(2200)
                }
            }
            StudioRendererKind::HtmlIframe => {
                if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                    1800
                } else {
                    materialization_max_tokens(renderer).min(2600)
                }
            }
            _ => 0,
        };
        if direct_author_budget > 0 {
            return direct_author_budget;
        }
    }

    materialization_max_tokens_for_runtime(renderer, runtime_kind)
}

fn format_timeout_duration(duration: Duration) -> String {
    if duration.as_secs() > 0 && duration.subsec_millis() == 0 {
        format!("{}s", duration.as_secs())
    } else {
        format!("{}ms", duration.as_millis())
    }
}

pub fn acceptance_timeout_for_execution_strategy(
    execution_strategy: StudioExecutionStrategy,
    runtime: &Arc<dyn InferenceRuntime>,
) -> Option<Duration> {
    if execution_strategy != StudioExecutionStrategy::DirectAuthor {
        return None;
    }

    if let Some(ms) = [
        "AUTOPILOT_STUDIO_ACCEPTANCE_TIMEOUT_MS",
        "IOI_STUDIO_ACCEPTANCE_TIMEOUT_MS",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<u64>().ok())
            .filter(|ms| *ms > 0)
    }) {
        return Some(Duration::from_millis(ms));
    }

    Some(match runtime.studio_runtime_provenance().kind {
        StudioRuntimeProvenanceKind::RealLocalRuntime => Duration::from_secs(20),
        StudioRuntimeProvenanceKind::FixtureRuntime
        | StudioRuntimeProvenanceKind::MockRuntime
        | StudioRuntimeProvenanceKind::DeterministicContinuityFallback
        | StudioRuntimeProvenanceKind::InferenceUnavailable => Duration::from_millis(50),
        _ => Duration::from_secs(15),
    })
}

pub(crate) fn materialization_repair_runtime_for_request(
    request: &StudioOutcomeArtifactRequest,
    production_runtime: &Arc<dyn InferenceRuntime>,
    repair_runtime: Option<&Arc<dyn InferenceRuntime>>,
) -> Arc<dyn InferenceRuntime> {
    let production_provenance = production_runtime.studio_runtime_provenance();
    if request.renderer == StudioRendererKind::HtmlIframe
        && production_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        if let Some(runtime) = repair_runtime {
            let repair_provenance = runtime.studio_runtime_provenance();
            if repair_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
                && !studio_runtime_provenance_matches(&repair_provenance, &production_provenance)
            {
                return runtime.clone();
            }
        }
    }

    production_runtime.clone()
}

fn should_warm_local_html_generation_runtime(
    request: &StudioOutcomeArtifactRequest,
    planning_runtime: &Arc<dyn InferenceRuntime>,
    production_runtime: &Arc<dyn InferenceRuntime>,
) -> bool {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return false;
    }

    let planning_provenance = planning_runtime.studio_runtime_provenance();
    let production_provenance = production_runtime.studio_runtime_provenance();
    production_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && planning_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && !studio_runtime_provenance_matches(&planning_provenance, &production_provenance)
}

fn local_html_generation_warmup_timeout() -> Duration {
    Duration::from_secs(12)
}

async fn warm_local_html_generation_runtime_if_needed(
    request: &StudioOutcomeArtifactRequest,
    planning_runtime: &Arc<dyn InferenceRuntime>,
    production_runtime: &Arc<dyn InferenceRuntime>,
) {
    if !should_warm_local_html_generation_runtime(request, planning_runtime, production_runtime) {
        return;
    }

    let production_provenance = production_runtime.studio_runtime_provenance();
    studio_generation_trace(format!(
        "artifact_generation:generation_warmup:start model={:?}",
        production_provenance.model
    ));
    match tokio::time::timeout(
        local_html_generation_warmup_timeout(),
        production_runtime.load_model([0u8; 32], Path::new("")),
    )
    .await
    {
        Ok(Ok(())) => studio_generation_trace(format!(
            "artifact_generation:generation_warmup:ok model={:?}",
            production_provenance.model
        )),
        Ok(Err(error)) => studio_generation_trace(format!(
            "artifact_generation:generation_warmup:error model={:?} error={}",
            production_provenance.model, error
        )),
        Err(_) => studio_generation_trace(format!(
            "artifact_generation:generation_warmup:timeout model={:?} timeout={}s",
            production_provenance.model,
            local_html_generation_warmup_timeout().as_secs()
        )),
    }
}

fn serialize_materialization_prompt_json<T: serde::Serialize>(
    value: &T,
    label: &str,
    compact: bool,
) -> Result<String, String> {
    if compact {
        serde_json::to_string(value)
            .map_err(|error| format!("Failed to serialize {label}: {error}"))
    } else {
        serde_json::to_string_pretty(value)
            .map_err(|error| format!("Failed to serialize {label}: {error}"))
    }
}

fn truncate_materialization_focus_text(raw: &str, max_chars: usize) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    let mut clipped = trimmed.chars().take(max_chars).collect::<String>();
    if trimmed.chars().count() > max_chars {
        clipped.push_str("...");
    }
    clipped
}

fn compact_local_html_materialization_request_focus(
    request: &StudioOutcomeArtifactRequest,
) -> serde_json::Value {
    json!({
        "artifactClass": request.artifact_class,
        "renderer": request.renderer,
        "presentationSurface": request.presentation_surface,
        "executionSubstrate": request.execution_substrate,
        "presentationVariantId": request.presentation_variant_id,
        "verification": {
            "requireRender": request.verification.require_render,
            "requireExport": request.verification.require_export,
        },
    })
}

fn compact_local_html_materialization_brief_focus(
    brief: &StudioArtifactBrief,
) -> serde_json::Value {
    json!({
        "audience": truncate_materialization_focus_text(&brief.audience, 80),
        "jobToBeDone": truncate_materialization_focus_text(&brief.job_to_be_done, 120),
        "subjectDomain": truncate_materialization_focus_text(&brief.subject_domain, 120),
        "artifactThesis": truncate_materialization_focus_text(&brief.artifact_thesis, 160),
        "requiredConcepts": brief
            .required_concepts
            .iter()
            .take(4)
            .map(|concept| truncate_materialization_focus_text(concept, 80))
            .collect::<Vec<_>>(),
        "requiredInteractions": brief
            .required_interactions
            .iter()
            .take(3)
            .map(|interaction| truncate_materialization_focus_text(interaction, 100))
            .collect::<Vec<_>>(),
        "visualTone": brief
            .visual_tone
            .iter()
            .take(3)
            .map(|tone| truncate_materialization_focus_text(tone, 48))
            .collect::<Vec<_>>(),
        "factualAnchors": brief
            .factual_anchors
            .iter()
            .take(3)
            .map(|anchor| truncate_materialization_focus_text(anchor, 120))
            .collect::<Vec<_>>(),
        "styleDirectives": brief
            .style_directives
            .iter()
            .take(3)
            .map(|directive| truncate_materialization_focus_text(directive, 120))
            .collect::<Vec<_>>(),
        "referenceHints": brief
            .reference_hints
            .iter()
            .take(2)
            .map(|hint| truncate_materialization_focus_text(hint, 120))
            .collect::<Vec<_>>(),
    })
}

fn compact_local_html_materialization_request_text(
    request: &StudioOutcomeArtifactRequest,
) -> String {
    [
        "renderer: html_iframe".to_string(),
        format!(
            "surface: {}",
            match request.presentation_surface {
                StudioPresentationSurface::Inline => "inline",
                StudioPresentationSurface::SidePanel => "side_panel",
                StudioPresentationSurface::Overlay => "overlay",
                StudioPresentationSurface::TabbedPanel => "tabbed_panel",
            }
        ),
        format!(
            "execution: {}",
            match request.execution_substrate {
                StudioExecutionSubstrate::None => "none",
                StudioExecutionSubstrate::ClientSandbox => "client_sandbox",
                StudioExecutionSubstrate::WorkspaceRuntime => "workspace_runtime",
                StudioExecutionSubstrate::BinaryGenerator => "binary_generator",
            }
        ),
        format!(
            "render verification: {}",
            request.verification.require_render
        ),
        format!("export required: {}", request.verification.require_export),
    ]
    .join("\n")
}

fn compact_local_html_materialization_brief_text(brief: &StudioArtifactBrief) -> String {
    let concepts = brief
        .required_concepts
        .iter()
        .take(3)
        .map(|concept| truncate_materialization_focus_text(concept, 48))
        .collect::<Vec<_>>()
        .join(" | ");
    let interactions = brief
        .required_interactions
        .iter()
        .take(2)
        .map(|interaction| truncate_materialization_focus_text(interaction, 64))
        .collect::<Vec<_>>()
        .join(" | ");
    let anchors = brief
        .factual_anchors
        .iter()
        .take(2)
        .map(|anchor| truncate_materialization_focus_text(anchor, 72))
        .collect::<Vec<_>>()
        .join(" | ");
    let tones = brief
        .visual_tone
        .iter()
        .take(2)
        .map(|tone| truncate_materialization_focus_text(tone, 32))
        .collect::<Vec<_>>()
        .join(" | ");
    let reference_hint = brief
        .reference_hints
        .iter()
        .find(|hint| !hint.trim().is_empty())
        .map(|hint| truncate_materialization_focus_text(hint, 72))
        .unwrap_or_else(|| "none".to_string());

    [
        format!(
            "audience: {}",
            truncate_materialization_focus_text(&brief.audience, 56)
        ),
        format!(
            "job: {}",
            truncate_materialization_focus_text(&brief.job_to_be_done, 96)
        ),
        format!(
            "domain: {}",
            truncate_materialization_focus_text(&brief.subject_domain, 72)
        ),
        format!(
            "thesis: {}",
            truncate_materialization_focus_text(&brief.artifact_thesis, 104)
        ),
        format!(
            "concepts: {}",
            if concepts.is_empty() {
                "none".to_string()
            } else {
                concepts
            }
        ),
        format!(
            "interactions: {}",
            if interactions.is_empty() {
                "none".to_string()
            } else {
                interactions
            }
        ),
        format!(
            "anchors: {}",
            if anchors.is_empty() {
                "none".to_string()
            } else {
                anchors
            }
        ),
        format!(
            "tone: {}",
            if tones.is_empty() {
                "none".to_string()
            } else {
                tones
            }
        ),
        format!("reference hint: {reference_hint}"),
    ]
    .join("\n")
}

fn compact_local_html_interaction_contract_text(brief: &StudioArtifactBrief) -> String {
    let contract = super::studio_artifact_interaction_contract(brief);
    [
        format!(
            "view switching required: {}",
            contract["viewSwitchingRequired"].as_bool().unwrap_or(false)
        ),
        format!(
            "rollover detail required: {}",
            contract["rolloverDetailRequired"]
                .as_bool()
                .unwrap_or(false)
        ),
        format!(
            "sequence browsing required: {}",
            contract["sequenceBrowsingRequired"]
                .as_bool()
                .unwrap_or(false)
        ),
    ]
    .join("\n")
}

fn direct_authoring_enabled(
    execution_strategy: StudioExecutionStrategy,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> bool {
    execution_strategy == StudioExecutionStrategy::DirectAuthor
        && direct_author_uses_raw_document(request)
        && refinement.is_none()
}

fn direct_author_uses_raw_document(request: &StudioOutcomeArtifactRequest) -> bool {
    matches!(
        request.renderer,
        StudioRendererKind::Markdown
            | StudioRendererKind::HtmlIframe
            | StudioRendererKind::Svg
            | StudioRendererKind::Mermaid
            | StudioRendererKind::PdfEmbed
    )
}

fn direct_author_stop_sequences(request: &StudioOutcomeArtifactRequest) -> Vec<String> {
    match request.renderer {
        StudioRendererKind::HtmlIframe => vec!["</html>".to_string()],
        StudioRendererKind::Svg => vec!["</svg>".to_string()],
        _ => Vec::new(),
    }
}

fn direct_author_completion_boundary(request: &StudioOutcomeArtifactRequest) -> Option<&'static str> {
    match request.renderer {
        StudioRendererKind::HtmlIframe => Some("</html>"),
        StudioRendererKind::Svg => Some("</svg>"),
        _ => None,
    }
}

fn direct_author_document_is_incomplete(
    request: &StudioOutcomeArtifactRequest,
    raw: &str,
    error_message: &str,
) -> bool {
    let Some(boundary) = direct_author_completion_boundary(request) else {
        return false;
    };

    if !raw.to_ascii_lowercase().contains(&boundary.to_ascii_lowercase()) {
        return true;
    }

    error_message.contains("fully closed </body></html> document")
        || error_message.contains("must contain a closing </svg>")
}

fn direct_author_continuation_pass_limit(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> usize {
    match request.renderer {
        StudioRendererKind::HtmlIframe | StudioRendererKind::Svg => {
            if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                2
            } else {
                1
            }
        }
        _ => 0,
    }
}

fn merge_direct_author_document(existing: &str, next: &str) -> String {
    let existing_trimmed = existing.trim_end();
    let next_trimmed = next.trim();
    if next_trimmed.is_empty() {
        return existing_trimmed.to_string();
    }

    if next_trimmed.starts_with("<!doctype html")
        || next_trimmed.starts_with("<html")
        || next_trimmed.starts_with("<svg")
    {
        return next_trimmed.to_string();
    }

    let existing_chars = existing_trimmed.chars().collect::<Vec<_>>();
    let next_chars = next_trimmed.chars().collect::<Vec<_>>();
    let max_overlap = existing_chars.len().min(next_chars.len()).min(512);
    let mut overlap = 0usize;
    for candidate in (1..=max_overlap).rev() {
        if existing_chars[existing_chars.len() - candidate..] == next_chars[..candidate] {
            overlap = candidate;
            break;
        }
    }

    let suffix = next_chars[overlap..].iter().collect::<String>();
    format!("{existing_trimmed}{suffix}")
}

fn compact_local_direct_author_prompt(
    runtime_kind: StudioRuntimeProvenanceKind,
    returns_raw_document: bool,
) -> bool {
    runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime && returns_raw_document
}

fn direct_author_brief(title: &str, intent: &str) -> StudioArtifactBrief {
    StudioArtifactBrief {
        audience: "the user".to_string(),
        job_to_be_done: "receive the requested artifact in one direct authoring pass".to_string(),
        subject_domain: if title.trim().is_empty() {
            "the requested subject".to_string()
        } else {
            title.trim().to_string()
        },
        artifact_thesis: intent.trim().to_string(),
        required_concepts: Vec::new(),
        required_interactions: Vec::new(),
        visual_tone: Vec::new(),
        factual_anchors: Vec::new(),
        style_directives: Vec::new(),
        reference_hints: Vec::new(),
    }
}

fn direct_author_search_budget(
    request: &StudioOutcomeArtifactRequest,
    production_kind: StudioRuntimeProvenanceKind,
) -> StudioAdaptiveSearchBudget {
    let max_semantic_refinement_passes = if renderer_supports_semantic_refinement(request.renderer)
    {
        1
    } else {
        0
    };
    StudioAdaptiveSearchBudget {
        initial_candidate_count: 1,
        max_candidate_count: 1,
        shortlist_limit: 1,
        max_semantic_refinement_passes,
        plateau_limit: usize::from(max_semantic_refinement_passes > 0),
        min_score_delta: if max_semantic_refinement_passes > 0 {
            1
        } else {
            i32::MAX
        },
        target_judge_score_for_early_stop: match request.renderer {
            StudioRendererKind::HtmlIframe => 356,
            StudioRendererKind::JsxSandbox => 348,
            StudioRendererKind::Svg => 340,
            StudioRendererKind::Markdown => 312,
            StudioRendererKind::Mermaid => 308,
            StudioRendererKind::PdfEmbed => 314,
            StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest => 306,
            StudioRendererKind::WorkspaceSurface => 300,
        },
        expansion_score_margin: 0,
        signals: if production_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
            vec![StudioAdaptiveSearchSignal::LocalGenerationConstraint]
        } else {
            Vec::new()
        },
    }
}

fn studio_direct_author_renderer_guidance(
    request: &StudioOutcomeArtifactRequest,
    candidate_seed: u64,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> String {
    match request.renderer {
        StudioRendererKind::Markdown => {
            "- Treat the raw user request as the dominant instruction.\n- Return only the finished markdown document body with request-specific headings, sections, and supporting detail.\n- Do not wrap the document in JSON or markdown fences.\n- Avoid generic platform framing, dashboards, or boilerplate artifact language."
                .to_string()
        }
        StudioRendererKind::HtmlIframe => {
            if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                return "- Treat the raw user request as the dominant instruction.\n- Author one concise self-contained index.html with inline CSS and inline JavaScript only.\n- Use standard HTML with <main> and at least three meaningful sections.\n- Keep first-paint content visible before scripts run, and include one real inline interaction that changes visible evidence or explanatory copy.\n- Keep the document request-specific, minimal, and fully closed with </html>."
                    .to_string();
            }
            let composition_recipe = match candidate_seed % 3 {
                0 => "editorial explainer with one strong evidence seam",
                1 => "guided comparison with visible state changes",
                _ => "annotated interactive narrative with focused data views",
            };
            let compact_runtime_note =
                if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
                    "- Keep the structure concise enough to reach a complete closing </main></body></html> in one pass.\n"
                } else {
                    ""
                };
            format!(
                "- Treat the raw user request as the dominant instruction. Do not translate it into a generic dashboard, control plane, or platform shell.\n- Compose a single self-contained index.html with inline CSS and inline JavaScript only.\n- Use standard HTML, open the body with <main>, and make the first paint complete before any script runs.\n- Follow this composition recipe for variety: {composition_recipe}.\n- If the request implies interaction, make the controls update visible evidence, comparison state, or explanatory copy on the page.\n- Prefer authored diagrams, comparisons, annotations, sceneboards, or guided explanation over app chrome.\n- Keep headings, labels, captions, and evidence specific to the request instead of generic artifact language.\n- Do not use placeholder copy, TODO markers, dead buttons, empty shells, or external libraries.\n{compact_runtime_note}- The artifact should feel authored for this exact request, not interchangeable with nearby prompts."
            )
        }
        StudioRendererKind::Svg => {
            "- Treat the raw user request as the dominant instruction.\n- Return only one complete standalone <svg> document with visible labels and enough marks to stand as the primary artifact.\n- Include <title> and <desc> when they help ground the request.\n- Do not wrap the SVG in JSON, prose, or markdown fences."
                .to_string()
        }
        StudioRendererKind::Mermaid => {
            "- Treat the raw user request as the dominant instruction.\n- Return only Mermaid source for one request-specific diagram.\n- Do not wrap the diagram in markdown fences or JSON.\n- Keep labels, nodes, and edges concrete to the request instead of generic platform language."
                .to_string()
        }
        StudioRendererKind::PdfEmbed => {
            "- Treat the raw user request as the dominant instruction.\n- Return only the authored document text that should be compiled into the PDF artifact.\n- Use clear sections and enough detail for a complete document, but do not emit LaTeX, JSON, or markdown fences.\n- Keep the document request-specific instead of generic artifact boilerplate."
                .to_string()
        }
        _ => "- Treat the raw user request as the dominant instruction and author the requested artifact directly."
            .to_string(),
    }
}

fn compact_local_html_refinement_context_focus(
    refinement: Option<&StudioArtifactRefinementContext>,
) -> serde_json::Value {
    let Some(refinement) = refinement else {
        return serde_json::Value::Null;
    };

    json!({
        "artifactId": refinement.artifact_id,
        "revisionId": refinement.revision_id,
        "title": truncate_materialization_focus_text(&refinement.title, 120),
        "summary": truncate_materialization_focus_text(&refinement.summary, 200),
        "renderer": refinement.renderer,
        "files": refinement
            .files
            .iter()
            .take(2)
            .map(|file| {
                json!({
                    "path": file.path,
                    "mime": file.mime,
                    "role": file.role,
                    "renderable": file.renderable,
                    "downloadable": file.downloadable,
                    "bodyChars": file.body.chars().count(),
                    "lineCount": file.body.lines().count(),
                })
            })
            .collect::<Vec<_>>(),
        "selectedTargets": refinement
            .selected_targets
            .iter()
            .take(3)
            .map(|target| {
                json!({
                    "sourceSurface": target.source_surface,
                    "path": target.path,
                    "label": truncate_materialization_focus_text(&target.label, 80),
                    "snippet": truncate_materialization_focus_text(&target.snippet, 160),
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn compact_local_html_refinement_candidate_focus(
    candidate: &StudioGeneratedArtifactPayload,
) -> serde_json::Value {
    json!({
        "summary": truncate_materialization_focus_text(&candidate.summary, 160),
        "notes": candidate
            .notes
            .iter()
            .take(2)
            .map(|note| truncate_materialization_focus_text(note, 160))
            .collect::<Vec<_>>(),
        "files": candidate
            .files
            .iter()
            .take(2)
            .map(|file| {
                json!({
                    "path": file.path,
                    "mime": file.mime,
                    "role": file.role,
                    "renderable": file.renderable,
                    "downloadable": file.downloadable,
                    "encoding": file.encoding,
                    "bodyChars": file.body.chars().count(),
                    "lineCount": file.body.lines().count(),
                    "bodyPreview": truncate_materialization_focus_text(&file.body, 1200),
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn compact_local_html_refinement_judge_focus(
    judge: &StudioArtifactJudgeResult,
) -> serde_json::Value {
    json!({
        "classification": judge.classification,
        "requestFaithfulness": judge.request_faithfulness,
        "conceptCoverage": judge.concept_coverage,
        "interactionRelevance": judge.interaction_relevance,
        "layoutCoherence": judge.layout_coherence,
        "visualHierarchy": judge.visual_hierarchy,
        "completeness": judge.completeness,
        "issueClasses": judge
            .issue_classes
            .iter()
            .take(3)
            .map(|item| truncate_materialization_focus_text(item, 80))
            .collect::<Vec<_>>(),
        "repairHints": judge
            .repair_hints
            .iter()
            .take(3)
            .map(|item| truncate_materialization_focus_text(item, 120))
            .collect::<Vec<_>>(),
        "strengths": judge
            .strengths
            .iter()
            .take(2)
            .map(|item| truncate_materialization_focus_text(item, 120))
            .collect::<Vec<_>>(),
        "fileFindings": judge
            .file_findings
            .iter()
            .take(2)
            .map(|item| truncate_materialization_focus_text(item, 140))
            .collect::<Vec<_>>(),
        "recommendedNextPass": judge.recommended_next_pass,
        "strongestContradiction": judge
            .strongest_contradiction
            .as_ref()
            .map(|value| truncate_materialization_focus_text(value, 140)),
        "rationale": truncate_materialization_focus_text(&judge.rationale, 160),
    })
}

fn extract_html_swarm_region_body(body: &str, region_id: &str) -> Option<String> {
    for candidate in html_swarm_region_id_variants(region_id) {
        let start_marker = html_swarm_region_marker_start(&candidate);
        let end_marker = html_swarm_region_marker_end(&candidate);
        let Some(start_index) = body.find(&start_marker) else {
            continue;
        };
        let content_start = start_index + start_marker.len();
        let relative_end_index = body[content_start..].find(&end_marker)?;
        let end_index = content_start + relative_end_index;
        return Some(body[content_start..end_index].trim().to_string());
    }
    None
}

fn extract_html_attribute_values(
    raw: &str,
    attribute: &str,
    split_whitespace: bool,
    max_items: usize,
) -> Vec<String> {
    let needle = format!("{attribute}=\"");
    let mut values = Vec::new();
    let mut search_start = 0usize;
    while values.len() < max_items {
        let Some(relative_start) = raw[search_start..].find(&needle) else {
            break;
        };
        let value_start = search_start + relative_start + needle.len();
        let Some(relative_end) = raw[value_start..].find('"') else {
            break;
        };
        let value_end = value_start + relative_end;
        let value = raw[value_start..value_end].trim();
        if !value.is_empty() {
            if split_whitespace {
                for item in value.split_whitespace() {
                    let item = item.trim();
                    if item.is_empty() || values.iter().any(|existing| existing == item) {
                        continue;
                    }
                    values.push(item.to_string());
                    if values.len() >= max_items {
                        break;
                    }
                }
            } else if !values.iter().any(|existing| existing == value) {
                values.push(value.to_string());
            }
        }
        search_start = value_end.saturating_add(1);
    }
    values
}

fn compact_local_html_dom_selector_hints(body: &str, max_items: usize) -> Vec<String> {
    let class_budget = max_items.min(8);
    let id_budget = max_items.min(6);
    let data_budget = max_items.min(8);
    let mut hints = Vec::<String>::new();

    for class_name in extract_html_attribute_values(body, "class", true, class_budget) {
        let selector = format!(".{class_name}");
        if !hints.iter().any(|existing| existing == &selector) {
            hints.push(selector);
        }
        if hints.len() >= max_items {
            return hints;
        }
    }
    for id in extract_html_attribute_values(body, "id", false, id_budget) {
        let selector = format!("#{id}");
        if !hints.iter().any(|existing| existing == &selector) {
            hints.push(selector);
        }
        if hints.len() >= max_items {
            return hints;
        }
    }
    for attr in [
        "data-phase",
        "data-target",
        "data-view",
        "data-view-panel",
        "data-detail",
        "data-control-phase",
        "data-control-risk",
    ] {
        for value in extract_html_attribute_values(body, attr, false, data_budget) {
            let selector = format!("[{attr}=\"{value}\"]");
            if !hints.iter().any(|existing| existing == &selector) {
                hints.push(selector);
            }
            if hints.len() >= max_items {
                return hints;
            }
        }
    }

    hints
}

fn compact_local_html_swarm_payload_focus(
    payload: &StudioGeneratedArtifactPayload,
    work_item: &StudioArtifactWorkItem,
) -> serde_json::Value {
    let body_preview_chars = match work_item.role {
        StudioArtifactWorkerRole::SectionContent => 0,
        StudioArtifactWorkerRole::StyleSystem | StudioArtifactWorkerRole::Interaction => 220,
        StudioArtifactWorkerRole::Integrator => 900,
        StudioArtifactWorkerRole::Repair => 280,
        _ => 520,
    };
    let owned_region_preview_chars = match work_item.role {
        StudioArtifactWorkerRole::SectionContent => 220,
        StudioArtifactWorkerRole::StyleSystem | StudioArtifactWorkerRole::Interaction => 420,
        StudioArtifactWorkerRole::Integrator => 1200,
        StudioArtifactWorkerRole::Repair => 360,
        _ => 520,
    };
    let owned_region_limit = match work_item.role {
        StudioArtifactWorkerRole::Repair => 3,
        _ => usize::MAX,
    };
    let owned_regions = payload
        .files
        .iter()
        .find(|file| file.path == "index.html")
        .map(|file| {
            work_item
                .write_regions
                .iter()
                .take(owned_region_limit)
                .map(|region_id| {
                    json!({
                        "regionId": region_id,
                        "bodyPreview": extract_html_swarm_region_body(&file.body, region_id)
                            .map(|body| truncate_materialization_focus_text(&body, owned_region_preview_chars))
                            .unwrap_or_default(),
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let dom_selector_hints = payload
        .files
        .iter()
        .find(|file| file.path == "index.html")
        .map(|file| {
            let selector_limit = match work_item.role {
                StudioArtifactWorkerRole::StyleSystem | StudioArtifactWorkerRole::Interaction => 14,
                StudioArtifactWorkerRole::Integrator => 18,
                StudioArtifactWorkerRole::Repair => 12,
                _ => 8,
            };
            compact_local_html_dom_selector_hints(&file.body, selector_limit)
        })
        .unwrap_or_default();

    json!({
        "summary": truncate_materialization_focus_text(&payload.summary, 160),
        "notes": payload
            .notes
            .iter()
            .take(3)
            .map(|note| truncate_materialization_focus_text(note, 120))
            .collect::<Vec<_>>(),
        "files": payload
            .files
            .iter()
            .take(2)
            .map(|file| {
                json!({
                    "path": file.path,
                    "mime": file.mime,
                    "role": file.role,
                    "renderable": file.renderable,
                    "downloadable": file.downloadable,
                    "encoding": file.encoding,
                    "bodyChars": file.body.chars().count(),
                    "lineCount": file.body.lines().count(),
                    "bodyPreview": if body_preview_chars == 0 {
                        String::new()
                    } else {
                        truncate_materialization_focus_text(&file.body, body_preview_chars)
                    },
                })
            })
            .collect::<Vec<_>>(),
        "ownedRegions": owned_regions,
        "domSelectorHints": dom_selector_hints,
    })
}

fn compact_local_html_swarm_work_item_focus(
    work_item: &StudioArtifactWorkItem,
) -> serde_json::Value {
    json!({
        "id": work_item.id,
        "role": work_item.role,
        "summary": truncate_materialization_focus_text(&work_item.summary, 140),
        "spawnedFromId": work_item.spawned_from_id,
        "writePaths": work_item.write_paths.iter().take(2).collect::<Vec<_>>(),
        "writeRegions": work_item.write_regions.iter().take(4).collect::<Vec<_>>(),
        "leaseRequirements": work_item
            .lease_requirements
            .iter()
            .take(4)
            .map(|lease| {
                json!({
                    "target": lease.target,
                    "scopeKind": lease.scope_kind,
                    "mode": lease.mode,
                })
            })
            .collect::<Vec<_>>(),
        "acceptanceCriteria": work_item
            .acceptance_criteria
            .iter()
            .take(4)
            .map(|item| truncate_materialization_focus_text(item, 100))
            .collect::<Vec<_>>(),
        "dependencyIds": work_item.dependency_ids.iter().take(4).collect::<Vec<_>>(),
        "blockedOnIds": work_item.blocked_on_ids.iter().take(4).collect::<Vec<_>>(),
        "verificationPolicy": work_item.verification_policy,
        "retryBudget": work_item.retry_budget,
    })
}

fn json_array_string_focus(
    value: Option<&serde_json::Value>,
    max_items: usize,
    max_chars: usize,
) -> Vec<String> {
    value
        .and_then(serde_json::Value::as_array)
        .map(|items| {
            items
                .iter()
                .take(max_items)
                .filter_map(serde_json::Value::as_str)
                .map(|item| truncate_materialization_focus_text(item, max_chars))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn compact_local_html_swarm_worker_context_focus(
    work_item: &StudioArtifactWorkItem,
    worker_context: &serde_json::Value,
) -> serde_json::Value {
    match work_item.role {
        StudioArtifactWorkerRole::SectionContent => {
            let section = worker_context.get("section");
            json!({
                "targetRegion": worker_context
                    .get("targetRegion")
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or_default(),
                "section": {
                    "id": section
                        .and_then(|value| value.get("id"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default(),
                    "role": section
                        .and_then(|value| value.get("role"))
                        .and_then(serde_json::Value::as_str)
                        .unwrap_or_default(),
                    "visiblePurpose": section
                        .and_then(|value| value.get("visiblePurpose"))
                        .and_then(serde_json::Value::as_str)
                        .map(|value| truncate_materialization_focus_text(value, 160))
                        .unwrap_or_default(),
                    "contentRequirements": json_array_string_focus(
                        section.and_then(|value| value.get("contentRequirements")),
                        4,
                        100,
                    ),
                    "interactionHooks": json_array_string_focus(
                        section.and_then(|value| value.get("interactionHooks")),
                        3,
                        90,
                    ),
                    "firstPaintRequirements": json_array_string_focus(
                        section.and_then(|value| value.get("firstPaintRequirements")),
                        4,
                        100,
                    ),
                },
            })
        }
        StudioArtifactWorkerRole::StyleSystem => json!({
            "designTokens": json_array_string_focus(
                worker_context.get("designTokens"),
                5,
                72,
            ),
            "colorStrategy": worker_context
                .get("colorStrategy")
                .and_then(serde_json::Value::as_str)
                .map(|value| truncate_materialization_focus_text(value, 120))
                .unwrap_or_default(),
            "density": worker_context
                .get("density")
                .and_then(serde_json::Value::as_str)
                .map(|value| truncate_materialization_focus_text(value, 80))
                .unwrap_or_default(),
        }),
        StudioArtifactWorkerRole::Interaction => json!({
            "interactionPlan": json_array_string_focus(
                worker_context.get("interactionPlan"),
                4,
                120,
            ),
            "interactionGraph": worker_context
                .get("interactionGraph")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
        }),
        StudioArtifactWorkerRole::Integrator => json!({
            "sectionPlan": worker_context
                .get("sectionPlan")
                .and_then(serde_json::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .take(4)
                        .map(|section| {
                            json!({
                                "id": section.get("id").and_then(serde_json::Value::as_str).unwrap_or_default(),
                                "role": section.get("role").and_then(serde_json::Value::as_str).unwrap_or_default(),
                                "visiblePurpose": section
                                    .get("visiblePurpose")
                                    .and_then(serde_json::Value::as_str)
                                    .map(|value| truncate_materialization_focus_text(value, 140))
                                    .unwrap_or_default(),
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            "interactionPlan": json_array_string_focus(
                worker_context.get("interactionPlan"),
                4,
                120,
            ),
            "judge": worker_context.get("judge").cloned().unwrap_or(serde_json::Value::Null),
        }),
        StudioArtifactWorkerRole::Repair => json!({
            "sectionPlan": worker_context
                .get("sectionPlan")
                .and_then(serde_json::Value::as_array)
                .map(|items| {
                    items
                        .iter()
                        .take(3)
                        .map(|section| {
                            json!({
                                "id": section.get("id").and_then(serde_json::Value::as_str).unwrap_or_default(),
                                "role": section.get("role").and_then(serde_json::Value::as_str).unwrap_or_default(),
                                "visiblePurpose": section
                                    .get("visiblePurpose")
                                    .and_then(serde_json::Value::as_str)
                                    .map(|value| truncate_materialization_focus_text(value, 96))
                                    .unwrap_or_default(),
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default(),
            "interactionPlan": json_array_string_focus(
                worker_context.get("interactionPlan"),
                2,
                96,
            ),
            "judge": compact_local_html_refinement_judge_focus(
                &serde_json::from_value::<StudioArtifactJudgeResult>(
                    worker_context.get("judge").cloned().unwrap_or(serde_json::Value::Null),
                )
                .unwrap_or_else(|_| blocked_candidate_generation_judge("Repair context judge summary unavailable.")),
            ),
        }),
        _ => worker_context.clone(),
    }
}

fn compact_local_html_swarm_renderer_guidance(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    work_item: &StudioArtifactWorkItem,
    candidate_seed: u64,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> String {
    match work_item.role {
        StudioArtifactWorkerRole::Skeleton => {
            "- Emit only a compact semantic HTML shell with region markers.\n- Keep copy terse and structural so later workers can own the real explanation.\n- Keep the index.html body compact and mostly single-line inside the JSON string so the patch envelope stays easy to parse.\n- Reserve the style-system and interaction regions without authoring real CSS rules or script logic.\n- Use short section wrappers with headings or stub labels only; do not author the finished visual system, simulator, or long explanatory prose in this step.".to_string()
        }
        StudioArtifactWorkerRole::SectionContent => {
            let target_region = work_item.write_regions.first().cloned().unwrap_or_default();
            let concept_focus = summarized_guidance_terms(
                &brief.required_concepts,
                "the request concepts",
                3,
            );
            let interaction_focus = summarized_guidance_terms(
                &brief.required_interactions,
                "the required interactions",
                2,
            );
            format!(
                "- Author only the semantic block inside {target_region}.\n- Make the section immediately useful on first paint with request-grounded explanation, labels, and concrete content.\n- Keep this section faithful to {concept_focus}.\n- If this section needs interaction, make it visibly tied to {interaction_focus} without rewriting the whole page.\n- Do not emit <style>, <script>, a duplicate page shell, or another hero unless the section purpose explicitly requires it.\n- Prefer one strong visual metaphor, diagram, comparison, or explainer block over stacked filler cards."
            )
        }
        StudioArtifactWorkerRole::StyleSystem => {
            "- Author CSS only.\n- Favor slate and graphite neutrals, dense readability, subtle borders, and one restrained cool accent.\n- Ground every selector to classes, ids, or data-* hooks already present in the current canonical artifact focus.\n- Do not invent parallel wrapper selectors, generic utility shells, or styles for classes/ids that are absent from the current artifact.\n- Improve hierarchy and spacing without changing copy or DOM structure.".to_string()
        }
        StudioArtifactWorkerRole::Interaction => {
            "- Author one compact inline script only.\n- Bind existing controls to visible on-page state changes.\n- Reference only classes, ids, and data-* hooks that already exist in the current canonical artifact focus.\n- Verify every selector you use resolves against the authored DOM; do not invent dead panel mappings or nonexistent targets.\n- Do not create the first meaningful content from script or rely on hidden panels as the main artifact.".to_string()
        }
        StudioArtifactWorkerRole::Integrator => {
            "- Repair only cross-section seams in the current merged artifact.\n- Preserve strong authored sections and avoid global rewrites.\n- Reuse the selectors, ids, and section structure already present in the canonical artifact instead of inventing a parallel shell.\n- Make the page feel like one coherent artifact, not multiple stitched drafts.".to_string()
        }
        StudioArtifactWorkerRole::Repair => {
            "- Patch only the cited failures in the current artifact.\n- Preserve strong authored content and avoid restarting from scratch.\n- Reuse selectors and structure already present in the canonical artifact whenever possible.\n- Prefer the smallest truthful change that fixes the blocked outcome.".to_string()
        }
        _ => studio_artifact_renderer_authoring_guidance_for_runtime(
            request,
            brief,
            candidate_seed,
            runtime_kind,
        ),
    }
}

fn compact_local_html_swarm_skill_focus(
    selected_skills: &[StudioArtifactSelectedSkill],
) -> serde_json::Value {
    json!(selected_skills
        .iter()
        .take(2)
        .map(|skill| {
            json!({
                "name": skill.name,
                "matchedNeedKinds": skill.matched_need_kinds,
                "matchRationale": truncate_materialization_focus_text(
                    &skill.match_rationale,
                    120,
                ),
            })
        })
        .collect::<Vec<_>>())
}

fn compact_local_html_swarm_exemplar_focus(
    exemplars: &[StudioArtifactExemplar],
) -> serde_json::Value {
    json!(exemplars
        .iter()
        .take(2)
        .map(|exemplar| {
            json!({
                "title": exemplar.title,
                "summary": truncate_materialization_focus_text(&exemplar.summary, 120),
                "scaffoldFamily": exemplar.scaffold_family,
                "designCues": exemplar.design_cues.iter().take(3).collect::<Vec<_>>(),
            })
        })
        .collect::<Vec<_>>())
}

fn compact_local_html_directives_text(directives: &str) -> String {
    directives
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .take(10)
        .map(|line| truncate_materialization_focus_text(line, 200))
        .collect::<Vec<_>>()
        .join("\n")
}

fn compact_local_html_materialization_repair_candidate_focus(
    raw_output: &str,
    request: &StudioOutcomeArtifactRequest,
) -> serde_json::Value {
    match super::parse_studio_generated_artifact_payload(raw_output) {
        Ok(mut candidate) => {
            super::normalize_generated_artifact_payload(&mut candidate, request);
            compact_local_html_refinement_candidate_focus(&candidate)
        }
        Err(_) => json!({
            "rawOutputPreview": truncate_candidate_failure_preview(raw_output, 1600),
        }),
    }
}

struct StudioSurfaceContractPromptBundle {
    design_label: &'static str,
    design_spine: Option<StudioHtmlPromotedDesignSkillSpine>,
    scaffold_label: &'static str,
    scaffold_contract: Option<StudioHtmlScaffoldContract>,
    component_label: &'static str,
    component_packs: Vec<StudioHtmlComponentPackContract>,
    execution_digest: String,
}

fn studio_surface_contract_prompt_bundle(
    brief: &StudioArtifactBrief,
    blueprint: &StudioArtifactBlueprint,
    artifact_ir: &StudioArtifactIR,
    selected_skills: &[StudioArtifactSelectedSkill],
    candidate_seed: u64,
) -> StudioSurfaceContractPromptBundle {
    match blueprint.renderer {
        StudioRendererKind::HtmlIframe => StudioSurfaceContractPromptBundle {
            design_label: "Studio promoted design skill spine",
            design_spine: studio_html_promoted_design_skill_spine(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
            ),
            scaffold_label: "Studio HTML scaffold contract",
            scaffold_contract: studio_html_scaffold_contract(
                blueprint,
                artifact_ir,
                candidate_seed,
            ),
            component_label: "Studio HTML component pack contracts",
            component_packs: studio_html_component_pack_contracts(blueprint),
            execution_digest: studio_html_scaffold_execution_digest(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                candidate_seed,
            )
            .unwrap_or_default(),
        },
        StudioRendererKind::JsxSandbox => StudioSurfaceContractPromptBundle {
            design_label: "Studio JSX design skill spine",
            design_spine: studio_jsx_promoted_design_skill_spine(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
            ),
            scaffold_label: "Studio JSX scaffold contract",
            scaffold_contract: studio_jsx_scaffold_contract(blueprint, artifact_ir, candidate_seed),
            component_label: "Studio JSX component pack contracts",
            component_packs: studio_jsx_component_pack_contracts(blueprint),
            execution_digest: studio_jsx_scaffold_execution_digest(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                candidate_seed,
            )
            .unwrap_or_default(),
        },
        StudioRendererKind::Svg => StudioSurfaceContractPromptBundle {
            design_label: "Studio SVG design skill spine",
            design_spine: studio_svg_promoted_design_skill_spine(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
            ),
            scaffold_label: "Studio SVG scaffold contract",
            scaffold_contract: studio_svg_scaffold_contract(blueprint, artifact_ir, candidate_seed),
            component_label: "Studio SVG component pack contracts",
            component_packs: studio_svg_component_pack_contracts(blueprint),
            execution_digest: studio_svg_scaffold_execution_digest(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                candidate_seed,
            )
            .unwrap_or_default(),
        },
        StudioRendererKind::PdfEmbed => StudioSurfaceContractPromptBundle {
            design_label: "Studio PDF design skill spine",
            design_spine: studio_pdf_promoted_design_skill_spine(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
            ),
            scaffold_label: "Studio PDF scaffold contract",
            scaffold_contract: studio_pdf_scaffold_contract(blueprint, artifact_ir, candidate_seed),
            component_label: "Studio PDF component pack contracts",
            component_packs: studio_pdf_component_pack_contracts(blueprint),
            execution_digest: studio_pdf_scaffold_execution_digest(
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                candidate_seed,
            )
            .unwrap_or_default(),
        },
        _ => StudioSurfaceContractPromptBundle {
            design_label: "Studio renderer design skill spine",
            design_spine: None,
            scaffold_label: "Studio renderer scaffold contract",
            scaffold_contract: None,
            component_label: "Studio renderer component pack contracts",
            component_packs: Vec::new(),
            execution_digest: String::new(),
        },
    }
}

#[derive(Clone)]
pub struct StudioArtifactResolvedRuntimePlan {
    pub policy: StudioArtifactRuntimePolicy,
    pub planning_runtime: Arc<dyn InferenceRuntime>,
    pub generation_runtime: Arc<dyn InferenceRuntime>,
    pub acceptance_runtime: Arc<dyn InferenceRuntime>,
    pub repair_runtime: Arc<dyn InferenceRuntime>,
}

fn studio_runtime_available(runtime: &Arc<dyn InferenceRuntime>) -> bool {
    runtime.studio_runtime_provenance().kind != StudioRuntimeProvenanceKind::InferenceUnavailable
}

fn normalized_runtime_endpoint(endpoint: Option<&str>) -> Option<String> {
    let endpoint = endpoint?.trim();
    if endpoint.is_empty() {
        return None;
    }

    let (without_fragment, fragment) = endpoint.split_once('#').unwrap_or((endpoint, ""));
    let Some((base, query)) = without_fragment.split_once('?') else {
        return Some(endpoint.to_string());
    };

    let filtered_pairs = query
        .split('&')
        .filter(|pair| {
            let key = pair
                .split_once('=')
                .map(|(key, _)| key)
                .unwrap_or(*pair)
                .trim();
            !key.is_empty() && !key.eq_ignore_ascii_case("lane")
        })
        .collect::<Vec<_>>();

    let mut normalized = base.to_string();
    if !filtered_pairs.is_empty() {
        normalized.push('?');
        normalized.push_str(&filtered_pairs.join("&"));
    }
    if !fragment.is_empty() {
        normalized.push('#');
        normalized.push_str(fragment);
    }

    Some(normalized)
}

fn studio_runtime_provenance_matches(
    left: &StudioRuntimeProvenance,
    right: &StudioRuntimeProvenance,
) -> bool {
    left.kind == right.kind
        && left.label == right.label
        && left.model == right.model
        && normalized_runtime_endpoint(left.endpoint.as_deref())
            == normalized_runtime_endpoint(right.endpoint.as_deref())
}

fn generation_runtime_tier(provenance: &StudioRuntimeProvenance) -> StudioArtifactRuntimeTier {
    match provenance.kind {
        StudioRuntimeProvenanceKind::RealLocalRuntime => StudioArtifactRuntimeTier::Local,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime
        | StudioRuntimeProvenanceKind::OpaqueRuntime => StudioArtifactRuntimeTier::CostEffective,
        StudioRuntimeProvenanceKind::DeterministicContinuityFallback
        | StudioRuntimeProvenanceKind::FixtureRuntime
        | StudioRuntimeProvenanceKind::MockRuntime
        | StudioRuntimeProvenanceKind::InferenceUnavailable => {
            StudioArtifactRuntimeTier::Deterministic
        }
    }
}

fn runtime_step_policies(
    profile: StudioArtifactRuntimePolicyProfile,
    renderer: StudioRendererKind,
) -> Vec<StudioArtifactRuntimeStepPolicy> {
    let premium_html_planning = matches!(
        renderer,
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
    );
    vec![
        StudioArtifactRuntimeStepPolicy {
            step: StudioArtifactRuntimeStep::OutcomeRouting,
            preferred_tier: StudioArtifactRuntimeTier::CostEffective,
            fallback_to_generation_runtime: true,
            require_distinct_runtime: false,
        },
        StudioArtifactRuntimeStepPolicy {
            step: StudioArtifactRuntimeStep::BlueprintPlanning,
            preferred_tier: match profile {
                StudioArtifactRuntimePolicyProfile::PremiumEndToEnd => {
                    StudioArtifactRuntimeTier::Premium
                }
                StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
                    if premium_html_planning =>
                {
                    StudioArtifactRuntimeTier::Premium
                }
                StudioArtifactRuntimePolicyProfile::FullyLocal
                | StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                | StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration => {
                    StudioArtifactRuntimeTier::Local
                }
                StudioArtifactRuntimePolicyProfile::Auto => {
                    StudioArtifactRuntimeTier::CostEffective
                }
            },
            fallback_to_generation_runtime: true,
            require_distinct_runtime: false,
        },
        StudioArtifactRuntimeStepPolicy {
            step: StudioArtifactRuntimeStep::CandidateGeneration,
            preferred_tier: match profile {
                StudioArtifactRuntimePolicyProfile::PremiumEndToEnd => {
                    StudioArtifactRuntimeTier::Premium
                }
                StudioArtifactRuntimePolicyProfile::FullyLocal
                | StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                | StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration => {
                    StudioArtifactRuntimeTier::Local
                }
                StudioArtifactRuntimePolicyProfile::Auto => {
                    StudioArtifactRuntimeTier::CostEffective
                }
            },
            fallback_to_generation_runtime: false,
            require_distinct_runtime: false,
        },
        StudioArtifactRuntimeStepPolicy {
            step: StudioArtifactRuntimeStep::AcceptanceJudge,
            preferred_tier: match profile {
                StudioArtifactRuntimePolicyProfile::FullyLocal => StudioArtifactRuntimeTier::Local,
                _ => StudioArtifactRuntimeTier::Premium,
            },
            fallback_to_generation_runtime: true,
            require_distinct_runtime: matches!(
                profile,
                StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                    | StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
            ),
        },
        StudioArtifactRuntimeStepPolicy {
            step: StudioArtifactRuntimeStep::RepairPlanning,
            preferred_tier: match profile {
                StudioArtifactRuntimePolicyProfile::FullyLocal => StudioArtifactRuntimeTier::Local,
                StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance => {
                    StudioArtifactRuntimeTier::Premium
                }
                StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
                    if premium_html_planning =>
                {
                    StudioArtifactRuntimeTier::Premium
                }
                StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration => {
                    StudioArtifactRuntimeTier::Local
                }
                StudioArtifactRuntimePolicyProfile::PremiumEndToEnd => {
                    StudioArtifactRuntimeTier::Premium
                }
                StudioArtifactRuntimePolicyProfile::Auto => {
                    StudioArtifactRuntimeTier::CostEffective
                }
            },
            fallback_to_generation_runtime: true,
            require_distinct_runtime: matches!(
                profile,
                StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
                    | StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
            ),
        },
        StudioArtifactRuntimeStepPolicy {
            step: StudioArtifactRuntimeStep::MemoryDistillation,
            preferred_tier: StudioArtifactRuntimeTier::Deterministic,
            fallback_to_generation_runtime: true,
            require_distinct_runtime: false,
        },
    ]
}

fn compact_local_specialist_generation_renderer(renderer: StudioRendererKind) -> bool {
    matches!(
        renderer,
        StudioRendererKind::Markdown
            | StudioRendererKind::DownloadCard
            | StudioRendererKind::BundleManifest
    )
}

fn compact_local_specialist_planning_renderer(renderer: StudioRendererKind) -> bool {
    matches!(
        renderer,
        StudioRendererKind::Markdown
            | StudioRendererKind::DownloadCard
            | StudioRendererKind::BundleManifest
    )
}

fn prefers_distinct_local_specialist_generation_runtime(
    profile: StudioArtifactRuntimePolicyProfile,
    request: &StudioOutcomeArtifactRequest,
    generation_provenance: &StudioRuntimeProvenance,
    acceptance_runtime: Option<&Arc<dyn InferenceRuntime>>,
) -> bool {
    if profile != StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
        || !compact_local_specialist_generation_renderer(request.renderer)
        || generation_provenance.kind != StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        return false;
    }

    let Some(runtime) = acceptance_runtime else {
        return false;
    };
    let acceptance_provenance = runtime.studio_runtime_provenance();
    acceptance_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && !studio_runtime_provenance_matches(&acceptance_provenance, generation_provenance)
}

fn prefers_distinct_local_specialist_planning_runtime(
    profile: StudioArtifactRuntimePolicyProfile,
    request: &StudioOutcomeArtifactRequest,
    generation_provenance: &StudioRuntimeProvenance,
    acceptance_runtime: Option<&Arc<dyn InferenceRuntime>>,
) -> bool {
    if profile != StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
        || !compact_local_specialist_planning_renderer(request.renderer)
        || generation_provenance.kind != StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        return false;
    }

    let Some(runtime) = acceptance_runtime else {
        return false;
    };
    let acceptance_provenance = runtime.studio_runtime_provenance();
    acceptance_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && !studio_runtime_provenance_matches(&acceptance_provenance, generation_provenance)
}

fn fallback_reason_for_premium_lane(
    acceptance_runtime: Option<&Arc<dyn InferenceRuntime>>,
    generation_provenance: &StudioRuntimeProvenance,
    require_distinct_runtime: bool,
) -> Option<String> {
    let Some(runtime) = acceptance_runtime else {
        return Some("acceptance_runtime_missing".to_string());
    };
    let acceptance_provenance = runtime.studio_runtime_provenance();
    if acceptance_provenance.kind == StudioRuntimeProvenanceKind::InferenceUnavailable {
        return Some("acceptance_runtime_unavailable".to_string());
    }
    if require_distinct_runtime
        && studio_runtime_provenance_matches(&acceptance_provenance, generation_provenance)
    {
        return Some("acceptance_runtime_not_distinct".to_string());
    }
    None
}

fn build_runtime_binding(
    step: StudioArtifactRuntimeStep,
    preferred_tier: StudioArtifactRuntimeTier,
    selected_tier: StudioArtifactRuntimeTier,
    runtime: &Arc<dyn InferenceRuntime>,
    fallback_reason: Option<String>,
) -> StudioArtifactRuntimeBinding {
    StudioArtifactRuntimeBinding {
        step,
        preferred_tier,
        selected_tier,
        fallback_applied: fallback_reason.is_some(),
        fallback_reason,
        provenance: runtime.studio_runtime_provenance(),
    }
}

pub fn resolve_studio_artifact_runtime_plan(
    request: &StudioOutcomeArtifactRequest,
    generation_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Option<Arc<dyn InferenceRuntime>>,
    requested_profile: StudioArtifactRuntimePolicyProfile,
) -> StudioArtifactResolvedRuntimePlan {
    let generation_provenance = generation_runtime.studio_runtime_provenance();
    let acceptance_available = acceptance_runtime
        .as_ref()
        .map(studio_runtime_available)
        .unwrap_or(false);
    let acceptance_distinct = acceptance_runtime
        .as_ref()
        .map(|runtime| {
            let provenance = runtime.studio_runtime_provenance();
            acceptance_available
                && !studio_runtime_provenance_matches(&provenance, &generation_provenance)
        })
        .unwrap_or(false);
    let resolved_profile = match requested_profile {
        StudioArtifactRuntimePolicyProfile::Auto => {
            if generation_provenance.kind == StudioRuntimeProvenanceKind::RealRemoteModelRuntime {
                StudioArtifactRuntimePolicyProfile::PremiumEndToEnd
            } else if acceptance_distinct {
                StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance
            } else {
                StudioArtifactRuntimePolicyProfile::FullyLocal
            }
        }
        other => other,
    };
    let step_policies = runtime_step_policies(resolved_profile, request.renderer);
    let generation_tier = generation_runtime_tier(&generation_provenance);
    let planning_policy = step_policies
        .iter()
        .find(|policy| policy.step == StudioArtifactRuntimeStep::BlueprintPlanning)
        .cloned()
        .expect("planning policy");
    let generation_policy = step_policies
        .iter()
        .find(|policy| policy.step == StudioArtifactRuntimeStep::CandidateGeneration)
        .cloned()
        .expect("generation policy");
    let acceptance_policy = step_policies
        .iter()
        .find(|policy| policy.step == StudioArtifactRuntimeStep::AcceptanceJudge)
        .cloned()
        .expect("acceptance policy");
    let repair_policy = step_policies
        .iter()
        .find(|policy| policy.step == StudioArtifactRuntimeStep::RepairPlanning)
        .cloned()
        .expect("repair policy");
    let compact_local_specialist_generation = prefers_distinct_local_specialist_generation_runtime(
        resolved_profile,
        request,
        &generation_provenance,
        acceptance_runtime.as_ref(),
    );
    let compact_local_specialist_acceptance = compact_local_specialist_generation;
    let compact_local_specialist_repair = compact_local_specialist_generation;
    let compact_local_specialist_planning = prefers_distinct_local_specialist_planning_runtime(
        resolved_profile,
        request,
        &generation_provenance,
        acceptance_runtime.as_ref(),
    );
    let planning_prefers_premium = matches!(
        resolved_profile,
        StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration
            | StudioArtifactRuntimePolicyProfile::PremiumEndToEnd
    ) && matches!(
        request.renderer,
        StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
    );
    let planning_fallback_reason = if planning_prefers_premium {
        fallback_reason_for_premium_lane(
            acceptance_runtime.as_ref(),
            &generation_provenance,
            planning_policy.require_distinct_runtime,
        )
    } else {
        None
    };
    let (planning_runtime, planning_binding) = if compact_local_specialist_planning {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("compact local specialist planning requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::BlueprintPlanning,
                planning_policy.preferred_tier,
                StudioArtifactRuntimeTier::Local,
                runtime,
                None,
            ),
        )
    } else if planning_prefers_premium && planning_fallback_reason.is_none() {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("premium planning requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::BlueprintPlanning,
                planning_policy.preferred_tier,
                StudioArtifactRuntimeTier::Premium,
                runtime,
                None,
            ),
        )
    } else {
        (
            generation_runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::BlueprintPlanning,
                planning_policy.preferred_tier,
                generation_tier,
                &generation_runtime,
                planning_fallback_reason,
            ),
        )
    };

    let generation_fallback_reason = if matches!(
        resolved_profile,
        StudioArtifactRuntimePolicyProfile::PremiumEndToEnd
    ) {
        fallback_reason_for_premium_lane(acceptance_runtime.as_ref(), &generation_provenance, false)
    } else {
        None
    };
    let (resolved_generation_runtime, generation_binding) = if compact_local_specialist_generation {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("compact local specialist generation requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::CandidateGeneration,
                generation_policy.preferred_tier,
                StudioArtifactRuntimeTier::Local,
                runtime,
                None,
            ),
        )
    } else if matches!(
        resolved_profile,
        StudioArtifactRuntimePolicyProfile::PremiumEndToEnd
    ) && generation_fallback_reason.is_none()
    {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("premium end-to-end requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::CandidateGeneration,
                generation_policy.preferred_tier,
                StudioArtifactRuntimeTier::Premium,
                runtime,
                None,
            ),
        )
    } else {
        (
            generation_runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::CandidateGeneration,
                generation_policy.preferred_tier,
                generation_tier,
                &generation_runtime,
                generation_fallback_reason,
            ),
        )
    };
    let resolved_generation_provenance = resolved_generation_runtime.studio_runtime_provenance();

    let acceptance_fallback_reason = if matches!(
        resolved_profile,
        StudioArtifactRuntimePolicyProfile::FullyLocal
    ) {
        None
    } else {
        fallback_reason_for_premium_lane(
            acceptance_runtime.as_ref(),
            &resolved_generation_provenance,
            acceptance_policy.require_distinct_runtime,
        )
    };
    let (resolved_acceptance_runtime, acceptance_binding) = if compact_local_specialist_acceptance {
        (
            resolved_generation_runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::AcceptanceJudge,
                acceptance_policy.preferred_tier,
                StudioArtifactRuntimeTier::Local,
                &resolved_generation_runtime,
                Some("compact_local_specialist_acceptance".to_string()),
            ),
        )
    } else if matches!(
        resolved_profile,
        StudioArtifactRuntimePolicyProfile::FullyLocal
    ) || acceptance_fallback_reason.is_some()
    {
        (
            generation_runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::AcceptanceJudge,
                acceptance_policy.preferred_tier,
                generation_tier,
                &generation_runtime,
                acceptance_fallback_reason,
            ),
        )
    } else {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("premium acceptance requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::AcceptanceJudge,
                acceptance_policy.preferred_tier,
                StudioArtifactRuntimeTier::Premium,
                runtime,
                None,
            ),
        )
    };

    let repair_prefers_premium = match resolved_profile {
        StudioArtifactRuntimePolicyProfile::FullyLocal => false,
        StudioArtifactRuntimePolicyProfile::LocalGenerationRemoteAcceptance => true,
        StudioArtifactRuntimePolicyProfile::PremiumPlanningLocalGeneration => matches!(
            request.renderer,
            StudioRendererKind::HtmlIframe | StudioRendererKind::JsxSandbox
        ),
        StudioArtifactRuntimePolicyProfile::PremiumEndToEnd => true,
        StudioArtifactRuntimePolicyProfile::Auto => false,
    };
    let repair_fallback_reason = if repair_prefers_premium
        && !matches!(
            resolved_profile,
            StudioArtifactRuntimePolicyProfile::FullyLocal
        ) {
        fallback_reason_for_premium_lane(
            acceptance_runtime.as_ref(),
            &resolved_generation_provenance,
            repair_policy.require_distinct_runtime,
        )
    } else {
        None
    };
    let (repair_runtime, repair_binding) = if compact_local_specialist_repair {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("compact local specialist repair requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::RepairPlanning,
                repair_policy.preferred_tier,
                StudioArtifactRuntimeTier::Local,
                runtime,
                Some("compact_local_specialist_repair".to_string()),
            ),
        )
    } else if repair_prefers_premium
        && repair_fallback_reason.is_none()
        && !matches!(
            resolved_profile,
            StudioArtifactRuntimePolicyProfile::FullyLocal
        )
    {
        let runtime = acceptance_runtime
            .as_ref()
            .expect("premium repair requires acceptance runtime");
        (
            runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::RepairPlanning,
                repair_policy.preferred_tier,
                StudioArtifactRuntimeTier::Premium,
                runtime,
                None,
            ),
        )
    } else {
        (
            generation_runtime.clone(),
            build_runtime_binding(
                StudioArtifactRuntimeStep::RepairPlanning,
                repair_policy.preferred_tier,
                generation_tier,
                &generation_runtime,
                repair_fallback_reason,
            ),
        )
    };

    StudioArtifactResolvedRuntimePlan {
        policy: StudioArtifactRuntimePolicy {
            profile: resolved_profile,
            step_policies,
            bindings: vec![
                planning_binding,
                generation_binding,
                acceptance_binding,
                repair_binding,
            ],
        },
        planning_runtime,
        generation_runtime: resolved_generation_runtime,
        acceptance_runtime: resolved_acceptance_runtime,
        repair_runtime,
    }
}

fn materialization_repair_candidate_view(
    raw_output: &str,
    request: &StudioOutcomeArtifactRequest,
) -> serde_json::Value {
    match super::parse_studio_generated_artifact_payload(raw_output) {
        Ok(mut candidate) => {
            super::normalize_generated_artifact_payload(&mut candidate, request);
            studio_artifact_refinement_candidate_view(&candidate)
        }
        Err(_) => json!({
            "rawOutputPreview": truncate_candidate_failure_preview(raw_output, 3600),
        }),
    }
}

fn merged_candidate_summaries(
    current: &[StudioArtifactCandidateSummary],
    failed: &[StudioArtifactCandidateSummary],
) -> Vec<StudioArtifactCandidateSummary> {
    let mut combined = current.to_vec();
    combined.extend(failed.iter().cloned());
    combined
}

fn derive_planning_context_for_request(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<StudioArtifactBlueprint>,
    artifact_ir: Option<StudioArtifactIR>,
    selected_skills: Vec<StudioArtifactSelectedSkill>,
) -> StudioArtifactPlanningContext {
    if request.renderer == StudioRendererKind::WorkspaceSurface {
        return StudioArtifactPlanningContext {
            brief: brief.clone(),
            blueprint: None,
            artifact_ir: None,
            selected_skills,
            retrieved_exemplars: Vec::new(),
        };
    }

    let resolved_blueprint =
        blueprint.unwrap_or_else(|| derive_studio_artifact_blueprint(request, brief));
    let resolved_artifact_ir = artifact_ir
        .unwrap_or_else(|| compile_studio_artifact_ir(request, brief, &resolved_blueprint));
    StudioArtifactPlanningContext {
        brief: brief.clone(),
        blueprint: Some(resolved_blueprint),
        artifact_ir: Some(resolved_artifact_ir),
        selected_skills,
        retrieved_exemplars: Vec::new(),
    }
}

fn studio_artifact_selected_skill_prompt_view(
    selected_skills: &[StudioArtifactSelectedSkill],
) -> serde_json::Value {
    serde_json::Value::Array(
        selected_skills
            .iter()
            .map(|skill| {
                json!({
                    "name": skill.name,
                    "description": skill.description,
                    "lifecycleState": skill.lifecycle_state,
                    "sourceType": skill.source_type,
                    "matchedNeedKinds": skill.matched_need_kinds,
                    "matchedNeedIds": skill.matched_need_ids,
                    "matchRationale": skill.match_rationale,
                    "relativePath": skill.relative_path,
                    "guidanceMarkdown": skill.guidance_markdown.as_ref().map(|markdown| {
                        let trimmed = markdown.trim();
                        let mut clipped = trimmed.chars().take(1800).collect::<String>();
                        if trimmed.chars().count() > 1800 {
                            clipped.push_str("...");
                        }
                        clipped
                    }),
                })
            })
            .collect(),
    )
}

fn studio_artifact_exemplar_prompt_view(exemplars: &[StudioArtifactExemplar]) -> serde_json::Value {
    serde_json::Value::Array(
        exemplars
            .iter()
            .map(|exemplar| {
                json!({
                    "recordId": exemplar.record_id,
                    "title": exemplar.title,
                    "summary": exemplar.summary,
                    "renderer": exemplar.renderer,
                    "scaffoldFamily": exemplar.scaffold_family,
                    "thesis": exemplar.thesis,
                    "qualityRationale": exemplar.quality_rationale,
                    "scoreTotal": exemplar.score_total,
                    "designCues": exemplar.design_cues,
                    "componentPatterns": exemplar.component_patterns,
                    "antiPatterns": exemplar.anti_patterns,
                    "sourceRevisionId": exemplar.source_revision_id,
                })
            })
            .collect(),
    )
}

fn blocked_candidate_generation_judge(message: &str) -> StudioArtifactJudgeResult {
    StudioArtifactJudgeResult {
        classification: StudioArtifactJudgeClassification::Blocked,
        request_faithfulness: 1,
        concept_coverage: 1,
        interaction_relevance: 1,
        layout_coherence: 1,
        visual_hierarchy: 1,
        completeness: 1,
        generic_shell_detected: false,
        trivial_shell_detected: false,
        deserves_primary_artifact_view: false,
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        issue_classes: vec!["generation_failure".to_string()],
        repair_hints: vec![
            "Regenerate a structurally valid candidate before acceptance judging.".to_string(),
        ],
        strengths: Vec::new(),
        blocked_reasons: vec![message.to_string()],
        file_findings: vec![format!("materialization: {}", message)],
        aesthetic_verdict: "No valid surfaced artifact exists yet.".to_string(),
        interaction_verdict: "Interaction quality cannot be judged until materialization succeeds."
            .to_string(),
        truthfulness_warnings: vec![
            "The candidate failed before producing a verifiable artifact.".to_string(),
        ],
        recommended_next_pass: Some("structural_repair".to_string()),
        strongest_contradiction: Some(message.to_string()),
        rationale: message.to_string(),
    }
}

fn failed_render_evaluation(
    request: &StudioOutcomeArtifactRequest,
    message: &str,
) -> StudioArtifactRenderEvaluation {
    StudioArtifactRenderEvaluation {
        supported: render_evaluation_required(request),
        first_paint_captured: false,
        interaction_capture_attempted: false,
        captures: Vec::new(),
        layout_density_score: 1,
        spacing_alignment_score: 1,
        typography_contrast_score: 1,
        visual_hierarchy_score: 1,
        blueprint_consistency_score: 1,
        overall_score: 1,
        findings: vec![StudioArtifactRenderFinding {
            code: "render_eval_failure".to_string(),
            severity: StudioArtifactRenderFindingSeverity::Blocked,
            summary: message.to_string(),
        }],
        summary: message.to_string(),
    }
}

pub(crate) fn render_evaluation_required(request: &StudioOutcomeArtifactRequest) -> bool {
    request.verification.require_render
        || matches!(
            request.renderer,
            StudioRendererKind::HtmlIframe | StudioRendererKind::Svg
        )
}

pub(crate) async fn evaluate_candidate_render_with_fallback(
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    edit_intent: Option<&StudioArtifactEditIntent>,
    candidate: &StudioGeneratedArtifactPayload,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Option<StudioArtifactRenderEvaluation> {
    if !render_evaluation_required(request) {
        studio_generation_trace(format!(
            "artifact_generation:render_eval:skip renderer={:?} reason=not_required",
            request.renderer
        ));
        return None;
    }
    let timeout = render_eval_timeout_for_runtime(request.renderer, runtime_kind);
    studio_generation_trace(format!(
        "artifact_generation:render_eval:start renderer={:?} timeout_ms={}",
        request.renderer,
        timeout.map(|value| value.as_millis()).unwrap_or(0)
    ));
    let evaluation = match timeout {
        Some(limit) => match tokio::time::timeout(
            limit,
            evaluate_studio_artifact_render_if_configured(
                render_evaluator,
                request,
                brief,
                blueprint,
                artifact_ir,
                edit_intent,
                candidate,
            ),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => Err(format!(
                "Render evaluation timed out after {} seconds.",
                limit.as_secs()
            )),
        },
        None => {
            evaluate_studio_artifact_render_if_configured(
                render_evaluator,
                request,
                brief,
                blueprint,
                artifact_ir,
                edit_intent,
                candidate,
            )
            .await
        }
    };

    match evaluation {
        Ok(render_evaluation) => {
            studio_generation_trace(format!(
                "artifact_generation:render_eval:ok renderer={:?} present={}",
                request.renderer,
                render_evaluation.is_some()
            ));
            render_evaluation
        }
        Err(error) => Some(failed_render_evaluation(
            request,
            &format!(
                "Render evaluation failed before Studio could verify the surfaced first paint: {}",
                error
            ),
        )),
    }
}

pub fn render_eval_timeout_for_runtime(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Option<Duration> {
    if renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        return Some(Duration::from_secs(20));
    }

    None
}

async fn judge_candidate_with_runtime_and_render_eval(
    runtime: Arc<dyn InferenceRuntime>,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
    title: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    candidate: &StudioGeneratedArtifactPayload,
) -> Result<StudioArtifactJudgeResult, String> {
    let judge = judge_studio_artifact_candidate_with_runtime_and_render_eval(
        runtime,
        title,
        request,
        brief,
        edit_intent,
        candidate,
        render_evaluation,
    )
    .await?;
    Ok(merge_studio_artifact_render_evaluation_into_judge(
        request,
        judge,
        render_evaluation,
    ))
}

async fn judge_candidate_with_runtime_and_render_eval_with_timeout(
    runtime: Arc<dyn InferenceRuntime>,
    acceptance_timeout: Option<Duration>,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
    title: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    candidate: &StudioGeneratedArtifactPayload,
) -> Result<StudioArtifactJudgeResult, String> {
    let judge = judge_candidate_with_runtime_and_render_eval(
        runtime,
        render_evaluation,
        title,
        request,
        brief,
        edit_intent,
        candidate,
    );
    match acceptance_timeout {
        Some(limit) => match tokio::time::timeout(limit, judge).await {
            Ok(result) => result,
            Err(_) => Err(format!(
                "Acceptance judging timed out after {}.",
                format_timeout_duration(limit)
            )),
        },
        None => judge.await,
    }
}

async fn materialize_and_locally_judge_candidate(
    production_runtime: Arc<dyn InferenceRuntime>,
    repair_runtime: Arc<dyn InferenceRuntime>,
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    seed: u64,
    temperature: f32,
    strategy: &str,
    origin: StudioArtifactOutputOrigin,
    model: &str,
    production_provenance: &StudioRuntimeProvenance,
) -> Result<
    (
        StudioArtifactCandidateSummary,
        StudioGeneratedArtifactPayload,
    ),
    StudioArtifactCandidateSummary,
> {
    studio_generation_trace(format!(
        "artifact_generation:candidate_materialize:start id={} seed={}",
        candidate_id, seed
    ));
    let payload = match materialize_studio_artifact_candidate_with_runtime_detailed(
        production_runtime.clone(),
        Some(repair_runtime),
        title,
        intent,
        request,
        brief,
        blueprint,
        artifact_ir,
        selected_skills,
        retrieved_exemplars,
        edit_intent,
        refinement,
        candidate_id,
        seed,
        temperature,
    )
    .await
    {
        Ok(payload) => {
            studio_generation_trace(format!(
                "artifact_generation:candidate_materialize:ok id={} files={}",
                candidate_id,
                payload.files.len()
            ));
            payload
        }
        Err(error) => {
            studio_generation_trace(format!(
                "artifact_generation:candidate_materialize:error id={} error={}",
                candidate_id, error.message
            ));
            let judge = blocked_candidate_generation_judge(&error.message);
            return Err(StudioArtifactCandidateSummary {
                candidate_id: candidate_id.to_string(),
                seed,
                model: model.to_string(),
                temperature,
                strategy: strategy.to_string(),
                origin,
                provenance: Some(production_provenance.clone()),
                summary: "Candidate failed during materialization.".to_string(),
                renderable_paths: Vec::new(),
                selected: false,
                fallback: false,
                failure: Some(error.message.clone()),
                raw_output_preview: error.raw_output_preview.clone(),
                convergence: Some(initial_candidate_convergence_trace(
                    candidate_id,
                    "generation_failure",
                    judge_total_score(&judge),
                )),
                render_evaluation: None,
                judge,
            });
        }
    };

    let render_evaluation = evaluate_candidate_render_with_fallback(
        render_evaluator,
        request,
        brief,
        blueprint,
        artifact_ir,
        edit_intent,
        &payload,
        production_provenance.kind,
    )
    .await;

    if production_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && matches!(
            request.renderer,
            StudioRendererKind::DownloadCard | StudioRendererKind::BundleManifest
        )
    {
        let judge = local_download_bundle_candidate_prejudge(request, brief, &payload);
        studio_generation_trace(format!(
            "artifact_generation:candidate_judge:deterministic id={} classification={:?}",
            candidate_id, judge.classification
        ));
        return Ok((
            StudioArtifactCandidateSummary {
                candidate_id: candidate_id.to_string(),
                seed,
                model: model.to_string(),
                temperature,
                strategy: strategy.to_string(),
                origin,
                provenance: Some(production_provenance.clone()),
                summary: payload.summary.clone(),
                renderable_paths: payload
                    .files
                    .iter()
                    .filter(|file| file.renderable)
                    .map(|file| file.path.clone())
                    .collect(),
                selected: false,
                fallback: false,
                failure: None,
                raw_output_preview: None,
                convergence: Some(initial_candidate_convergence_trace(
                    candidate_id,
                    "initial_generation",
                    judge_total_score(&judge),
                )),
                render_evaluation,
                judge,
            },
            payload,
        ));
    }

    studio_generation_trace(format!(
        "artifact_generation:candidate_judge:start id={}",
        candidate_id
    ));
    let judge = match judge_candidate_with_runtime_and_render_eval(
        production_runtime,
        render_evaluation.as_ref(),
        title,
        request,
        brief,
        edit_intent,
        &payload,
    )
    .await
    {
        Ok(judge) => {
            studio_generation_trace(format!(
                "artifact_generation:candidate_judge:ok id={} classification={:?}",
                candidate_id, judge.classification
            ));
            judge
        }
        Err(error) => {
            studio_generation_trace(format!(
                "artifact_generation:candidate_judge:error id={} error={}",
                candidate_id, error
            ));
            let judge = blocked_candidate_generation_judge(&format!("judge failed: {error}"));
            return Err(StudioArtifactCandidateSummary {
                candidate_id: candidate_id.to_string(),
                seed,
                model: model.to_string(),
                temperature,
                strategy: strategy.to_string(),
                origin,
                provenance: Some(production_provenance.clone()),
                summary: payload.summary.clone(),
                renderable_paths: payload
                    .files
                    .iter()
                    .filter(|file| file.renderable)
                    .map(|file| file.path.clone())
                    .collect(),
                selected: false,
                fallback: false,
                failure: Some(format!("judge failed: {error}")),
                raw_output_preview: None,
                convergence: Some(initial_candidate_convergence_trace(
                    candidate_id,
                    "judge_failure",
                    judge_total_score(&judge),
                )),
                render_evaluation,
                judge,
            });
        }
    };

    Ok((
        StudioArtifactCandidateSummary {
            candidate_id: candidate_id.to_string(),
            seed,
            model: model.to_string(),
            temperature,
            strategy: strategy.to_string(),
            origin,
            provenance: Some(production_provenance.clone()),
            summary: payload.summary.clone(),
            renderable_paths: payload
                .files
                .iter()
                .filter(|file| file.renderable)
                .map(|file| file.path.clone())
                .collect(),
            selected: false,
            fallback: false,
            failure: None,
            raw_output_preview: None,
            convergence: Some(initial_candidate_convergence_trace(
                candidate_id,
                "initial_generation",
                judge_total_score(&judge),
            )),
            render_evaluation,
            judge,
        },
        payload,
    ))
}

fn local_download_bundle_candidate_prejudge(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    payload: &StudioGeneratedArtifactPayload,
) -> StudioArtifactJudgeResult {
    let has_readme = payload
        .files
        .iter()
        .any(|file| file.path.eq_ignore_ascii_case("README.md") && !file.body.trim().is_empty());
    let export_files = payload
        .files
        .iter()
        .filter(|file| file.downloadable)
        .collect::<Vec<_>>();
    let has_csv_export = export_files.iter().any(|file| {
        (file.path.to_ascii_lowercase().ends_with(".csv") || file.mime == "text/csv")
            && file.body.lines().count() >= 2
            && file.body.contains(',')
    });
    let required_terms = brief
        .required_concepts
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect::<Vec<_>>();
    let body = payload
        .files
        .iter()
        .map(|file| file.body.as_str())
        .collect::<Vec<_>>()
        .join("\n");
    let body_lower = body.to_ascii_lowercase();
    let concept_hits = required_terms
        .iter()
        .filter(|term| !term.is_empty() && body_lower.contains(term.as_str()))
        .count();
    let all_downloadable = payload.files.iter().all(|file| file.downloadable);
    let classification = if has_readme && has_csv_export && all_downloadable {
        StudioArtifactJudgeClassification::Pass
    } else if has_readme || has_csv_export {
        StudioArtifactJudgeClassification::Repairable
    } else {
        StudioArtifactJudgeClassification::Blocked
    };
    let request_faithfulness = if has_readme && has_csv_export { 4 } else { 2 };
    let concept_coverage = if concept_hits >= brief.required_concepts.len().min(2).max(1) {
        4
    } else if has_readme && has_csv_export {
        3
    } else {
        2
    };
    let completeness = if has_readme && has_csv_export { 4 } else { 2 };
    let deserves_primary_artifact_view = classification == StudioArtifactJudgeClassification::Pass;
    let mut strengths = Vec::new();
    if has_readme {
        strengths.push("README.md is present for bundle guidance.".to_string());
    }
    if has_csv_export {
        strengths.push("CSV export is present with tabular rows.".to_string());
    }
    let mut blocked_reasons = Vec::new();
    if !has_readme {
        blocked_reasons.push("Bundle is missing a usable README.md.".to_string());
    }
    if !has_csv_export {
        blocked_reasons.push("Bundle is missing a usable CSV export.".to_string());
    }
    if !all_downloadable {
        blocked_reasons.push("All bundle files must remain downloadable.".to_string());
    }
    let rationale = match &classification {
        StudioArtifactJudgeClassification::Pass => {
            "Download bundle includes the required files with usable contents.".to_string()
        }
        StudioArtifactJudgeClassification::Repairable => {
            "Download bundle is close, but a required file is thin or incomplete.".to_string()
        }
        StudioArtifactJudgeClassification::Blocked => {
            "Download bundle is missing a required usable file.".to_string()
        }
    };

    let recommended_next_pass = match &classification {
        StudioArtifactJudgeClassification::Pass => "accept",
        StudioArtifactJudgeClassification::Repairable => "structural_repair",
        StudioArtifactJudgeClassification::Blocked => "hold_block",
    }
    .to_string();

    super::enforce_renderer_judge_contract(
        request,
        brief,
        payload,
        StudioArtifactJudgeResult {
            classification,
            request_faithfulness,
            concept_coverage,
            interaction_relevance: 4,
            layout_coherence: 4,
            visual_hierarchy: 4,
            completeness,
            generic_shell_detected: false,
            trivial_shell_detected: !(has_readme || has_csv_export),
            deserves_primary_artifact_view,
            patched_existing_artifact: None,
            continuity_revision_ux: None,
            issue_classes: Vec::new(),
            repair_hints: Vec::new(),
            strengths,
            blocked_reasons,
            file_findings: Vec::new(),
            aesthetic_verdict: String::new(),
            interaction_verdict: String::new(),
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: Some(recommended_next_pass),
            strongest_contradiction: None,
            rationale,
        },
    )
}

fn local_draft_fast_path_enabled(
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    production_provenance: &StudioRuntimeProvenance,
    acceptance_provenance: &StudioRuntimeProvenance,
) -> bool {
    refinement.is_none()
        && production_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && acceptance_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && (matches!(
            request.renderer,
            StudioRendererKind::JsxSandbox | StudioRendererKind::Svg
        ) || (request.renderer == StudioRendererKind::HtmlIframe
            && studio_modal_first_html_enabled()))
}

fn judge_supports_local_draft_surface(judge: &StudioArtifactJudgeResult) -> bool {
    judge.classification != StudioArtifactJudgeClassification::Blocked
        && judge.deserves_primary_artifact_view
        && !judge.generic_shell_detected
        && !judge.trivial_shell_detected
}

fn candidate_supports_pending_draft_surface(summary: &StudioArtifactCandidateSummary) -> bool {
    if summary.renderable_paths.is_empty()
        || summary.judge.classification == StudioArtifactJudgeClassification::Blocked
    {
        return false;
    }

    summary
        .render_evaluation
        .as_ref()
        .map(|evaluation| {
            !evaluation.supported
                || (evaluation.first_paint_captured
                    && evaluation.findings.iter().all(|finding| {
                        finding.severity != StudioArtifactRenderFindingSeverity::Blocked
                    }))
        })
        .unwrap_or(true)
}

fn direct_author_provisional_candidate_judge(
    payload: &StudioGeneratedArtifactPayload,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
) -> StudioArtifactJudgeResult {
    let renderable_paths = payload
        .files
        .iter()
        .filter(|file| file.renderable)
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    let blocked_render_finding = render_evaluation.and_then(|evaluation| {
        evaluation
            .findings
            .iter()
            .find(|finding| finding.severity == StudioArtifactRenderFindingSeverity::Blocked)
    });
    let classification = if renderable_paths.is_empty() || blocked_render_finding.is_some() {
        StudioArtifactJudgeClassification::Blocked
    } else {
        StudioArtifactJudgeClassification::Repairable
    };
    let mut blocked_reasons = Vec::new();
    if renderable_paths.is_empty() {
        blocked_reasons.push("Direct authoring did not surface a renderable document.".to_string());
    }
    if let Some(finding) = blocked_render_finding {
        blocked_reasons.push(finding.summary.clone());
    }
    let mut issue_classes = Vec::new();
    let mut repair_hints = Vec::new();
    if let Some(evaluation) = render_evaluation {
        for finding in evaluation.findings.iter().take(3) {
            if !issue_classes.contains(&finding.code) {
                issue_classes.push(finding.code.clone());
            }
            if repair_hints.len() < 3 {
                repair_hints.push(finding.summary.clone());
            }
        }
    }
    let rationale = if classification == StudioArtifactJudgeClassification::Blocked {
        blocked_reasons
            .first()
            .cloned()
            .unwrap_or_else(|| "Direct-authored draft could not be surfaced for acceptance.".to_string())
    } else {
        "Studio surfaced a renderable direct-authored draft and is ready for final acceptance verification."
            .to_string()
    };
    StudioArtifactJudgeResult {
        classification,
        request_faithfulness: if renderable_paths.is_empty() { 1 } else { 3 },
        concept_coverage: if renderable_paths.is_empty() { 1 } else { 3 },
        interaction_relevance: if renderable_paths.is_empty() { 1 } else { 3 },
        layout_coherence: if renderable_paths.is_empty() { 1 } else { 3 },
        visual_hierarchy: if renderable_paths.is_empty() { 1 } else { 3 },
        completeness: if renderable_paths.is_empty() { 1 } else { 3 },
        generic_shell_detected: false,
        trivial_shell_detected: renderable_paths.is_empty(),
        deserves_primary_artifact_view: !renderable_paths.is_empty() && blocked_render_finding.is_none(),
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        issue_classes,
        repair_hints,
        strengths: if renderable_paths.is_empty() {
            Vec::new()
        } else {
            vec!["Renderable direct-authored draft surfaced before final acceptance.".to_string()]
        },
        blocked_reasons,
        file_findings: renderable_paths
            .iter()
            .map(|path| format!("draft surfaced: {path}"))
            .collect(),
        aesthetic_verdict: if renderable_paths.is_empty() {
            "No renderable direct-authored draft surfaced yet.".to_string()
        } else {
            "Renderable draft surfaced; final acceptance review is still pending.".to_string()
        },
        interaction_verdict: if renderable_paths.is_empty() {
            "Interaction quality cannot be judged until a renderable file exists.".to_string()
        } else {
            "Interaction acceptance is deferred to the dedicated acceptance pass.".to_string()
        },
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some(
            if classification == StudioArtifactJudgeClassification::Blocked {
                "structural_repair"
            } else {
                "accept"
            }
            .to_string(),
        ),
        strongest_contradiction: blocked_render_finding.map(|finding| finding.summary.clone()),
        rationale,
    }
}

fn direct_author_should_defer_render_evaluation(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> bool {
    runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && matches!(request.renderer, StudioRendererKind::HtmlIframe)
}

fn local_draft_pending_acceptance_judge(
    judge: &StudioArtifactJudgeResult,
    strongest_contradiction: Option<String>,
    rationale: Option<String>,
) -> StudioArtifactJudgeResult {
    let mut draft_judge = judge.clone();
    draft_judge.classification = StudioArtifactJudgeClassification::Repairable;
    draft_judge.blocked_reasons.clear();
    let contradiction = strongest_contradiction
        .unwrap_or_else(|| "Acceptance judging is still pending for this draft.".to_string());
    draft_judge.strongest_contradiction = Some(contradiction);
    draft_judge.rationale = rationale.unwrap_or_else(|| {
        "Production surfaced a request-faithful local draft while stronger acceptance judging remains pending."
            .to_string()
    });
    draft_judge.recommended_next_pass = Some("acceptance_retry".to_string());
    draft_judge
}

fn build_non_swarm_draft_bundle(
    request: &StudioOutcomeArtifactRequest,
    brief: StudioArtifactBrief,
    blueprint: Option<StudioArtifactBlueprint>,
    artifact_ir: Option<StudioArtifactIR>,
    selected_skills: Vec<StudioArtifactSelectedSkill>,
    edit_intent: Option<StudioArtifactEditIntent>,
    mut candidate_summaries: Vec<StudioArtifactCandidateSummary>,
    failed_candidate_summaries: &[StudioArtifactCandidateSummary],
    candidate_rows: &[(
        StudioArtifactCandidateSummary,
        StudioGeneratedArtifactPayload,
    )],
    winner_index: usize,
    draft_judge: StudioArtifactJudgeResult,
    termination_reason: &str,
    execution_strategy: StudioExecutionStrategy,
    origin: StudioArtifactOutputOrigin,
    production_provenance: StudioRuntimeProvenance,
    acceptance_provenance: StudioRuntimeProvenance,
    runtime_policy: StudioArtifactRuntimePolicy,
    adaptive_search_budget: StudioAdaptiveSearchBudget,
    taste_memory: Option<StudioArtifactTasteMemory>,
    live_previews: &[ExecutionLivePreview],
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    if let Some(selected) = candidate_summaries.get_mut(winner_index) {
        selected.selected = true;
        update_candidate_summary_judge(selected, draft_judge.clone());
        set_candidate_termination_reason(selected, termination_reason);
    }
    let winner_summary = candidate_summaries
        .get(winner_index)
        .cloned()
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio winning draft candidate summary is missing.".to_string(),
            brief: Some(brief.clone()),
            blueprint: blueprint.clone(),
            artifact_ir: artifact_ir.clone(),
            selected_skills: selected_skills.clone(),
            edit_intent: edit_intent.clone(),
            candidate_summaries: merged_candidate_summaries(
                &candidate_summaries,
                failed_candidate_summaries,
            ),
        })?;
    let winner = candidate_rows
        .get(winner_index)
        .map(|(_, payload)| payload.clone())
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio winning draft artifact payload is missing.".to_string(),
            brief: Some(brief.clone()),
            blueprint: blueprint.clone(),
            artifact_ir: artifact_ir.clone(),
            selected_skills: selected_skills.clone(),
            edit_intent: edit_intent.clone(),
            candidate_summaries: merged_candidate_summaries(
                &candidate_summaries,
                failed_candidate_summaries,
            ),
        })?;
    let final_candidate_summaries =
        merged_candidate_summaries(&candidate_summaries, failed_candidate_summaries);
    let execution_envelope = build_non_swarm_execution_envelope(
        request,
        execution_strategy,
        live_previews,
        ExecutionCompletionInvariantStatus::Pending,
        non_swarm_required_artifact_paths(&winner),
    );

    Ok(StudioArtifactGenerationBundle {
        brief,
        blueprint,
        artifact_ir,
        selected_skills,
        edit_intent,
        candidate_summaries: final_candidate_summaries,
        winning_candidate_id: Some(winner_summary.candidate_id.clone()),
        winning_candidate_rationale: Some(draft_judge.rationale.clone()),
        execution_envelope,
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        judge: draft_judge,
        winner,
        render_evaluation: winner_summary.render_evaluation.clone(),
        origin,
        production_provenance,
        acceptance_provenance,
        runtime_policy: Some(runtime_policy),
        adaptive_search_budget: Some(adaptive_search_budget),
        fallback_used: false,
        ux_lifecycle: StudioArtifactUxLifecycle::Draft,
        taste_memory,
        failure: None,
    })
}

fn record_adaptive_search_signal(
    signals: &mut Vec<StudioAdaptiveSearchSignal>,
    signal: StudioAdaptiveSearchSignal,
) {
    if !signals.contains(&signal) {
        signals.push(signal);
    }
}

fn renderer_candidate_cap(
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

fn renderer_shortlist_cap(renderer: StudioRendererKind) -> usize {
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

fn renderer_refinement_cap(
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
        .required_interactions
        .len()
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

fn top_candidate_score_gap(
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

#[derive(Debug, Clone, Copy)]
struct SemanticConvergenceBudget {
    max_passes: usize,
    plateau_limit: usize,
    min_score_delta: i32,
}

fn semantic_convergence_budget(
    adaptive_budget: &StudioAdaptiveSearchBudget,
) -> SemanticConvergenceBudget {
    SemanticConvergenceBudget {
        max_passes: adaptive_budget.max_semantic_refinement_passes,
        plateau_limit: adaptive_budget.plateau_limit,
        min_score_delta: adaptive_budget.min_score_delta,
    }
}

pub(super) fn requested_follow_up_pass(judge: &StudioArtifactJudgeResult) -> Option<&'static str> {
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

fn refinement_temperature_for_pass(pass_kind: &str) -> f32 {
    match pass_kind {
        "polish_pass" => 0.1,
        "structural_repair" => 0.18,
        _ => 0.18,
    }
}

fn initial_candidate_convergence_trace(
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

fn refined_candidate_convergence_trace(
    source_summary: &StudioArtifactCandidateSummary,
    pass_kind: &str,
    score_total: i32,
    score_delta_from_parent: i32,
) -> StudioArtifactCandidateConvergenceTrace {
    let (lineage_root_id, pass_index) = source_summary
        .convergence
        .as_ref()
        .map(|trace| (trace.lineage_root_id.clone(), trace.pass_index + 1))
        .unwrap_or_else(|| {
            (
                refined_candidate_root(&source_summary.candidate_id).to_string(),
                1,
            )
        });
    StudioArtifactCandidateConvergenceTrace {
        lineage_root_id,
        parent_candidate_id: Some(source_summary.candidate_id.clone()),
        pass_kind: pass_kind.to_string(),
        pass_index,
        score_total,
        score_delta_from_parent: Some(score_delta_from_parent),
        terminated_reason: None,
    }
}

fn update_candidate_summary_judge(
    summary: &mut StudioArtifactCandidateSummary,
    judge: StudioArtifactJudgeResult,
) {
    summary.judge = judge.clone();
    if let Some(convergence) = summary.convergence.as_mut() {
        convergence.score_total = judge_total_score(&judge);
    }
}

fn set_candidate_termination_reason(
    summary: &mut StudioArtifactCandidateSummary,
    reason: impl Into<String>,
) {
    if let Some(convergence) = summary.convergence.as_mut() {
        convergence.terminated_reason = Some(reason.into());
    }
}

struct SemanticRefinementProgress {
    selected_winner_index: Option<usize>,
    best_acceptance_index: Option<usize>,
    best_acceptance_score: i32,
}

async fn attempt_semantic_refinement_for_candidate(
    repair_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Arc<dyn InferenceRuntime>,
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    strategy: &str,
    origin: StudioArtifactOutputOrigin,
    repair_model: &str,
    repair_provenance: &StudioRuntimeProvenance,
    adaptive_search_budget: &StudioAdaptiveSearchBudget,
    source_index: usize,
    candidate_rows: &mut Vec<(
        StudioArtifactCandidateSummary,
        StudioGeneratedArtifactPayload,
    )>,
    candidate_summaries: &mut Vec<StudioArtifactCandidateSummary>,
    refined_candidate_roots: &mut std::collections::HashSet<String>,
    mut best_acceptance_index: Option<usize>,
    mut best_acceptance_score: i32,
) -> Result<SemanticRefinementProgress, StudioArtifactGenerationError> {
    let budget = semantic_convergence_budget(adaptive_search_budget);
    let mut refinement_source_index = source_index;
    let mut plateau_count = 0usize;
    let refinement_root = candidate_summaries
        .get(refinement_source_index)
        .map(|summary| refined_candidate_root(&summary.candidate_id).to_string())
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio best candidate summary is missing for refinement.".to_string(),
            brief: Some(brief.clone()),
            blueprint: blueprint.cloned(),
            artifact_ir: artifact_ir.cloned(),
            selected_skills: selected_skills.to_vec(),
            edit_intent: edit_intent.cloned(),
            candidate_summaries: candidate_summaries.clone(),
        })?;
    if !refined_candidate_roots.insert(refinement_root) {
        return Ok(SemanticRefinementProgress {
            selected_winner_index: None,
            best_acceptance_index,
            best_acceptance_score,
        });
    }

    for refinement_pass in 0..budget.max_passes {
        let source_summary = candidate_summaries
            .get(refinement_source_index)
            .cloned()
            .ok_or_else(|| StudioArtifactGenerationError {
                message: "Studio best candidate summary is missing for refinement.".to_string(),
                brief: Some(brief.clone()),
                blueprint: blueprint.cloned(),
                artifact_ir: artifact_ir.cloned(),
                selected_skills: selected_skills.to_vec(),
                edit_intent: edit_intent.cloned(),
                candidate_summaries: candidate_summaries.clone(),
            })?;
        let Some(pass_kind) = requested_follow_up_pass(&source_summary.judge) else {
            if let Some(summary) = candidate_summaries.get_mut(refinement_source_index) {
                set_candidate_termination_reason(summary, "judge_requested_stop");
            }
            break;
        };
        let source_payload = candidate_rows
            .get(refinement_source_index)
            .map(|(_, payload)| payload.clone())
            .ok_or_else(|| StudioArtifactGenerationError {
                message: "Studio best candidate payload is missing for refinement.".to_string(),
                brief: Some(brief.clone()),
                blueprint: blueprint.cloned(),
                artifact_ir: artifact_ir.cloned(),
                selected_skills: selected_skills.to_vec(),
                edit_intent: edit_intent.cloned(),
                candidate_summaries: candidate_summaries.clone(),
            })?;
        let refined_candidate_id = format!(
            "{}-refine-{}",
            refined_candidate_root(&source_summary.candidate_id),
            refinement_pass + 1
        );
        studio_generation_trace(format!(
            "artifact_generation:refine:start id={} source={}",
            refined_candidate_id, source_summary.candidate_id
        ));
        let refined_payload = match refine_studio_artifact_candidate_with_runtime(
            repair_runtime.clone(),
            title,
            intent,
            request,
            brief,
            blueprint,
            artifact_ir,
            selected_skills,
            retrieved_exemplars,
            edit_intent,
            refinement,
            &source_payload,
            &source_summary.judge,
            &refined_candidate_id,
            source_summary.seed,
            refinement_temperature_for_pass(pass_kind),
        )
        .await
        {
            Ok(payload) => payload,
            Err(error) => {
                if let Some(summary) = candidate_summaries.get_mut(refinement_source_index) {
                    set_candidate_termination_reason(
                        summary,
                        format!("refinement_failed: {}", error),
                    );
                }
                studio_generation_trace(format!(
                    "artifact_generation:refine:error id={} error={}",
                    refined_candidate_id, error
                ));
                break;
            }
        };
        studio_generation_trace(format!(
            "artifact_generation:refine:ok id={} files={}",
            refined_candidate_id,
            refined_payload.files.len()
        ));
        studio_generation_trace(format!(
            "artifact_generation:refine_acceptance:start id={}",
            refined_candidate_id
        ));
        let refined_render_evaluation = evaluate_candidate_render_with_fallback(
            render_evaluator,
            request,
            brief,
            blueprint,
            artifact_ir,
            edit_intent,
            &refined_payload,
            repair_provenance.kind,
        )
        .await;
        let refined_acceptance_judge = judge_candidate_with_runtime_and_render_eval(
            acceptance_runtime.clone(),
            refined_render_evaluation.as_ref(),
            title,
            request,
            brief,
            edit_intent,
            &refined_payload,
        )
        .await
        .map_err(|message| StudioArtifactGenerationError {
            message,
            brief: Some(brief.clone()),
            blueprint: blueprint.cloned(),
            artifact_ir: artifact_ir.cloned(),
            selected_skills: selected_skills.to_vec(),
            edit_intent: edit_intent.cloned(),
            candidate_summaries: candidate_summaries.clone(),
        })?;
        studio_generation_trace(format!(
            "artifact_generation:refine_acceptance:ok id={} classification={:?}",
            refined_candidate_id, refined_acceptance_judge.classification
        ));
        let refined_score = judge_total_score(&refined_acceptance_judge);
        let source_score = judge_total_score(&source_summary.judge);
        let score_delta_from_parent = refined_score - source_score;
        let refined_summary = StudioArtifactCandidateSummary {
            candidate_id: refined_candidate_id,
            seed: source_summary.seed,
            model: repair_model.to_string(),
            temperature: refinement_temperature_for_pass(pass_kind),
            strategy: format!("{strategy}.{pass_kind}"),
            origin,
            provenance: Some(repair_provenance.clone()),
            summary: refined_payload.summary.clone(),
            renderable_paths: refined_payload
                .files
                .iter()
                .filter(|file| file.renderable)
                .map(|file| file.path.clone())
                .collect(),
            selected: false,
            fallback: false,
            failure: None,
            raw_output_preview: None,
            convergence: Some(refined_candidate_convergence_trace(
                &source_summary,
                pass_kind,
                refined_score,
                score_delta_from_parent,
            )),
            render_evaluation: refined_render_evaluation,
            judge: refined_acceptance_judge.clone(),
        };
        let refined_index = candidate_rows.len();
        candidate_summaries.push(refined_summary.clone());
        candidate_rows.push((refined_summary, refined_payload));
        if refined_score > best_acceptance_score {
            best_acceptance_score = refined_score;
            best_acceptance_index = Some(refined_index);
        }
        if judge_clears_primary_view(&refined_acceptance_judge) {
            if let Some(summary) = candidate_summaries.get_mut(refined_index) {
                set_candidate_termination_reason(summary, "cleared_primary_view");
            }
            return Ok(SemanticRefinementProgress {
                selected_winner_index: Some(refined_index),
                best_acceptance_index,
                best_acceptance_score,
            });
        }
        if score_delta_from_parent >= budget.min_score_delta {
            plateau_count = 0;
            refinement_source_index = refined_index;
            continue;
        }
        plateau_count += 1;
        if let Some(summary) = candidate_summaries.get_mut(refined_index) {
            let termination = if score_delta_from_parent < 0 {
                "regressed_after_rejudge"
            } else {
                "plateau_after_rejudge"
            };
            set_candidate_termination_reason(summary, termination);
        }
        if plateau_count >= budget.plateau_limit.max(1) {
            break;
        }
        refinement_source_index = refined_index;
    }

    if let Some(summary) = candidate_summaries.get_mut(refinement_source_index) {
        if summary
            .convergence
            .as_ref()
            .and_then(|trace| trace.terminated_reason.as_ref())
            .is_none()
        {
            set_candidate_termination_reason(summary, "repair_budget_exhausted");
        }
    }

    Ok(SemanticRefinementProgress {
        selected_winner_index: None,
        best_acceptance_index,
        best_acceptance_score,
    })
}

#[derive(Debug, Clone, Copy, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(crate) enum StudioArtifactPatchOperationKind {
    CreateFile,
    ReplaceFile,
    ReplaceRegion,
    DeleteFile,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioArtifactPatchOperation {
    pub(crate) kind: StudioArtifactPatchOperationKind,
    pub(crate) path: String,
    #[serde(default)]
    pub(crate) region_id: Option<String>,
    #[serde(default)]
    pub(crate) mime: Option<String>,
    #[serde(default)]
    pub(crate) role: Option<StudioArtifactFileRole>,
    #[serde(default)]
    pub(crate) renderable: Option<bool>,
    #[serde(default)]
    pub(crate) downloadable: Option<bool>,
    #[serde(default)]
    pub(crate) encoding: Option<StudioGeneratedArtifactEncoding>,
    #[serde(default)]
    pub(crate) body: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub(crate) struct StudioArtifactPatchEnvelope {
    #[serde(default)]
    pub(crate) summary: Option<String>,
    #[serde(default)]
    pub(crate) notes: Vec<String>,
    #[serde(default)]
    pub(crate) operations: Vec<StudioArtifactPatchOperation>,
}

fn coalesce_html_swarm_section_plans(
    sections: Vec<StudioArtifactSectionPlan>,
    max_sections: usize,
) -> Vec<StudioArtifactSectionPlan> {
    if sections.len() <= max_sections.max(1) {
        return sections;
    }

    let chunk_size = sections.len().div_ceil(max_sections.max(1));
    sections
        .chunks(chunk_size)
        .enumerate()
        .map(|(index, chunk)| {
            let mut content_requirements = Vec::new();
            let mut interaction_hooks = Vec::new();
            let mut first_paint_requirements = Vec::new();
            for section in chunk {
                push_unique_focus_strings(
                    &mut content_requirements,
                    section.content_requirements.clone(),
                    5,
                );
                push_unique_focus_strings(
                    &mut interaction_hooks,
                    section.interaction_hooks.clone(),
                    4,
                );
                push_unique_focus_strings(
                    &mut first_paint_requirements,
                    section.first_paint_requirements.clone(),
                    5,
                );
            }
            let id = chunk
                .first()
                .map(|section| section.id.clone())
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| format!("section-{}", index + 1));
            let role = if chunk.len() == 1 {
                chunk[0].role.clone()
            } else {
                format!("composite-{}", index + 1)
            };
            let visible_purpose = chunk
                .iter()
                .take(2)
                .map(|section| truncate_materialization_focus_text(&section.visible_purpose, 96))
                .collect::<Vec<_>>()
                .join(" Then ");
            StudioArtifactSectionPlan {
                id,
                role,
                visible_purpose,
                content_requirements,
                interaction_hooks,
                first_paint_requirements,
            }
        })
        .collect()
}

fn fallback_section_plans() -> Vec<StudioArtifactSectionPlan> {
    vec![
        StudioArtifactSectionPlan {
            id: "lead".to_string(),
            role: "lead".to_string(),
            visible_purpose: "Establish the request thesis and the first useful state.".to_string(),
            content_requirements: vec!["First-paint framing".to_string()],
            interaction_hooks: Vec::new(),
            first_paint_requirements: vec!["Visible opening state".to_string()],
        },
        StudioArtifactSectionPlan {
            id: "evidence".to_string(),
            role: "evidence".to_string(),
            visible_purpose: "Surface the request-grounded evidence or explanation.".to_string(),
            content_requirements: vec!["Primary evidence view".to_string()],
            interaction_hooks: Vec::new(),
            first_paint_requirements: vec!["Visible evidence".to_string()],
        },
        StudioArtifactSectionPlan {
            id: "detail".to_string(),
            role: "detail".to_string(),
            visible_purpose: "Carry the supporting detail, comparison, or call to action."
                .to_string(),
            content_requirements: vec!["Secondary depth".to_string()],
            interaction_hooks: Vec::new(),
            first_paint_requirements: vec!["Secondary surfaced depth".to_string()],
        },
    ]
}

pub(crate) fn build_studio_artifact_swarm_plan(
    request: &StudioOutcomeArtifactRequest,
    blueprint: Option<&StudioArtifactBlueprint>,
    brief: &StudioArtifactBrief,
    execution_strategy: StudioExecutionStrategy,
) -> StudioArtifactSwarmPlan {
    let (strategy, adapter_label) = studio_swarm_strategy_for_request(request, execution_strategy);
    let is_micro_swarm = execution_strategy == StudioExecutionStrategy::MicroSwarm;
    let mut work_items = vec![StudioArtifactWorkItem {
        id: "planner".to_string(),
        title: "Planner".to_string(),
        role: StudioArtifactWorkerRole::Planner,
        summary: "Lock the artifact outline, constraints, and worker ownership map once."
            .to_string(),
        spawned_from_id: None,
        read_paths: Vec::new(),
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        lease_requirements: Vec::new(),
        acceptance_criteria: vec![
            "Work graph is dependency ordered.".to_string(),
            "Writable scopes are explicit.".to_string(),
        ],
        dependency_ids: Vec::new(),
        blocked_on_ids: Vec::new(),
        verification_policy: Some(SwarmVerificationPolicy::Normal),
        retry_budget: Some(0),
        status: StudioArtifactWorkItemStatus::Pending,
    }];

    match request.renderer {
        StudioRendererKind::HtmlIframe => {
            let sections = blueprint
                .map(|value| value.section_plan.clone())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(fallback_section_plans);
            let sections =
                coalesce_html_swarm_section_plans(sections, if is_micro_swarm { 1 } else { 3 });
            let section_regions = sections
                .iter()
                .enumerate()
                .map(|(index, section)| format!("section:{}", section_region_id(section, index)))
                .collect::<Vec<_>>();
            work_items.push(StudioArtifactWorkItem {
                id: "skeleton".to_string(),
                title: "HTML skeleton".to_string(),
                role: StudioArtifactWorkerRole::Skeleton,
                summary: "Author the canonical HTML shell and region map.".to_string(),
                spawned_from_id: None,
                read_paths: Vec::new(),
                write_paths: vec!["index.html".to_string()],
                write_regions: {
                    let mut regions = vec!["style-system".to_string(), "interaction".to_string()];
                    regions.extend(section_regions.clone());
                    regions
                },
                lease_requirements: {
                    let mut leases = vec![exclusive_write_lease_for_path("index.html")];
                    leases.extend(
                        std::iter::once("style-system".to_string())
                            .chain(std::iter::once("interaction".to_string()))
                            .chain(section_regions.clone().into_iter())
                            .map(exclusive_write_lease_for_region),
                    );
                    leases
                },
                acceptance_criteria: vec![
                    "The shell includes <main> and the section region markers.".to_string(),
                    "Style and interaction regions are reserved once.".to_string(),
                ],
                dependency_ids: vec!["planner".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: Some(SwarmVerificationPolicy::Normal),
                retry_budget: Some(0),
                status: StudioArtifactWorkItemStatus::Pending,
            });
            for (index, section) in sections.iter().enumerate() {
                let region_id = format!("section:{}", section_region_id(section, index));
                work_items.push(StudioArtifactWorkItem {
                    id: format!("section-{}", index + 1),
                    title: format!("Section {}", index + 1),
                    role: StudioArtifactWorkerRole::SectionContent,
                    summary: format!(
                        "Own the {} section content without rewriting global shell.",
                        section.role
                    ),
                    spawned_from_id: None,
                    read_paths: vec!["index.html".to_string()],
                    write_paths: vec!["index.html".to_string()],
                    write_regions: vec![region_id.clone()],
                    lease_requirements: vec![
                        shared_read_lease_for_path("index.html"),
                        exclusive_write_lease_for_region(region_id),
                    ],
                    acceptance_criteria: {
                        let mut criteria = vec![section.visible_purpose.clone()];
                        criteria.extend(section.first_paint_requirements.clone());
                        criteria
                    },
                    dependency_ids: vec!["skeleton".to_string()],
                    blocked_on_ids: Vec::new(),
                    verification_policy: Some(SwarmVerificationPolicy::Normal),
                    retry_budget: Some(0),
                    status: StudioArtifactWorkItemStatus::Pending,
                });
            }
            let section_dependency_ids = work_items
                .iter()
                .filter(|item| item.role == StudioArtifactWorkerRole::SectionContent)
                .map(|item| item.id.clone())
                .collect::<Vec<_>>();
            if !is_micro_swarm {
                work_items.push(StudioArtifactWorkItem {
                    id: "style-system".to_string(),
                    title: "Style system".to_string(),
                    role: StudioArtifactWorkerRole::StyleSystem,
                    summary: "Own shared tokens, hierarchy, and palette coherence.".to_string(),
                    spawned_from_id: None,
                    read_paths: vec!["index.html".to_string()],
                    write_paths: vec!["index.html".to_string()],
                    write_regions: vec!["style-system".to_string()],
                    lease_requirements: vec![
                        shared_read_lease_for_path("index.html"),
                        exclusive_write_lease_for_region("style-system"),
                    ],
                    acceptance_criteria: vec![
                        "Slate/graphite shell with one cool accent family.".to_string(),
                        "Dense but readable hierarchy.".to_string(),
                    ],
                    dependency_ids: {
                        let mut deps = vec!["skeleton".to_string()];
                        deps.extend(section_dependency_ids.clone());
                        deps
                    },
                    blocked_on_ids: Vec::new(),
                    verification_policy: Some(SwarmVerificationPolicy::Elevated),
                    retry_budget: Some(0),
                    status: StudioArtifactWorkItemStatus::Pending,
                });
                work_items.push(StudioArtifactWorkItem {
                    id: "interaction".to_string(),
                    title: "Interaction".to_string(),
                    role: StudioArtifactWorkerRole::Interaction,
                    summary: "Wire the chosen interaction grammar against authored DOM."
                        .to_string(),
                    spawned_from_id: None,
                    read_paths: vec!["index.html".to_string()],
                    write_paths: vec!["index.html".to_string()],
                    write_regions: vec!["interaction".to_string()],
                    lease_requirements: vec![
                        shared_read_lease_for_path("index.html"),
                        exclusive_write_lease_for_region("interaction"),
                    ],
                    acceptance_criteria: {
                        let mut criteria = brief.required_interactions.clone();
                        if criteria.is_empty() {
                            criteria.push(
                                "Keep authored state changes truthful and inline.".to_string(),
                            );
                        }
                        criteria
                    },
                    dependency_ids: {
                        let mut deps = section_dependency_ids.clone();
                        deps.push("skeleton".to_string());
                        deps
                    },
                    blocked_on_ids: Vec::new(),
                    verification_policy: Some(SwarmVerificationPolicy::Elevated),
                    retry_budget: Some(0),
                    status: StudioArtifactWorkItemStatus::Pending,
                });
                work_items.push(StudioArtifactWorkItem {
                    id: "integrator".to_string(),
                    title: "Integrator".to_string(),
                    role: StudioArtifactWorkerRole::Integrator,
                    summary: "Reconcile cross-section seams without restarting the document."
                        .to_string(),
                    spawned_from_id: None,
                    read_paths: vec!["index.html".to_string()],
                    write_paths: vec!["index.html".to_string()],
                    write_regions: {
                        let mut regions =
                            vec!["style-system".to_string(), "interaction".to_string()];
                        regions.extend(section_regions);
                        regions
                    },
                    lease_requirements: {
                        let mut leases = vec![shared_read_lease_for_path("index.html")];
                        leases.extend(
                            work_items
                                .iter()
                                .filter(|item| {
                                    item.role == StudioArtifactWorkerRole::SectionContent
                                })
                                .flat_map(|item| item.write_regions.clone())
                                .chain(vec!["style-system".to_string(), "interaction".to_string()])
                                .map(exclusive_write_lease_for_region),
                        );
                        leases
                    },
                    acceptance_criteria: vec![
                        "Cross-section copy and utility hierarchy agree.".to_string(),
                        "The first paint reads as one cohesive artifact.".to_string(),
                    ],
                    dependency_ids: {
                        let mut deps = vec!["style-system".to_string(), "interaction".to_string()];
                        deps.extend(section_dependency_ids);
                        deps
                    },
                    blocked_on_ids: Vec::new(),
                    verification_policy: Some(SwarmVerificationPolicy::Elevated),
                    retry_budget: Some(0),
                    status: StudioArtifactWorkItemStatus::Pending,
                });
            }
        }
        _ => {
            let primary_file = default_generated_artifact_file_for_renderer(request.renderer);
            work_items.push(StudioArtifactWorkItem {
                id: "skeleton".to_string(),
                title: "Coarse implementer".to_string(),
                role: StudioArtifactWorkerRole::Skeleton,
                summary:
                    "Materialize the initial renderer-native file set under one bounded worker."
                        .to_string(),
                spawned_from_id: None,
                read_paths: Vec::new(),
                write_paths: vec![primary_file.path.clone()],
                write_regions: Vec::new(),
                lease_requirements: vec![exclusive_write_lease_for_path(primary_file.path.clone())],
                acceptance_criteria: vec![
                    "Create the canonical primary file set once.".to_string(),
                    "Stay inside the renderer contract.".to_string(),
                ],
                dependency_ids: vec!["planner".to_string()],
                blocked_on_ids: Vec::new(),
                verification_policy: Some(SwarmVerificationPolicy::Normal),
                retry_budget: Some(0),
                status: StudioArtifactWorkItemStatus::Pending,
            });
            if !is_micro_swarm {
                work_items.push(StudioArtifactWorkItem {
                    id: "integrator".to_string(),
                    title: "Integrator".to_string(),
                    role: StudioArtifactWorkerRole::Integrator,
                    summary: "Apply bounded reconciliation only when the coarse adapter needs it."
                        .to_string(),
                    spawned_from_id: None,
                    read_paths: vec![primary_file.path],
                    write_paths: Vec::new(),
                    write_regions: Vec::new(),
                    lease_requirements: Vec::new(),
                    acceptance_criteria: vec![
                        "Do not rewrite the artifact without a cited verification reason."
                            .to_string(),
                    ],
                    dependency_ids: vec!["skeleton".to_string()],
                    blocked_on_ids: Vec::new(),
                    verification_policy: Some(SwarmVerificationPolicy::Elevated),
                    retry_budget: Some(0),
                    status: StudioArtifactWorkItemStatus::Pending,
                });
            }
        }
    }

    let repair_write_paths = if request.renderer == StudioRendererKind::HtmlIframe {
        work_items
            .iter()
            .flat_map(|item| item.write_paths.iter().cloned())
            .fold(Vec::<String>::new(), |mut acc, path| {
                if !acc.iter().any(|existing| existing == &path) {
                    acc.push(path);
                }
                acc
            })
    } else {
        Vec::new()
    };
    let repair_write_regions = if request.renderer == StudioRendererKind::HtmlIframe {
        work_items
            .iter()
            .flat_map(|item| item.write_regions.iter().cloned())
            .fold(Vec::<String>::new(), |mut acc, region| {
                if !acc.iter().any(|existing| existing == &region) {
                    acc.push(region);
                }
                acc
            })
    } else {
        Vec::new()
    };

    let judge_dependency_ids = work_items
        .iter()
        .filter(|item| item.role == StudioArtifactWorkerRole::Integrator)
        .map(|item| item.id.clone())
        .collect::<Vec<_>>();
    work_items.push(StudioArtifactWorkItem {
        id: "judge".to_string(),
        title: "Judge".to_string(),
        role: StudioArtifactWorkerRole::Judge,
        summary: "Evaluate the merged artifact once against fidelity, utility, and coherence."
            .to_string(),
        spawned_from_id: None,
        read_paths: Vec::new(),
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        lease_requirements: Vec::new(),
        acceptance_criteria: vec!["Judge the merged artifact, not competing universes.".to_string()],
        dependency_ids: if judge_dependency_ids.is_empty() {
            work_items
                .iter()
                .filter(|item| {
                    matches!(
                        item.role,
                        StudioArtifactWorkerRole::Skeleton
                            | StudioArtifactWorkerRole::SectionContent
                            | StudioArtifactWorkerRole::StyleSystem
                            | StudioArtifactWorkerRole::Interaction
                            | StudioArtifactWorkerRole::Integrator
                    )
                })
                .map(|item| item.id.clone())
                .collect()
        } else {
            judge_dependency_ids
        },
        blocked_on_ids: Vec::new(),
        verification_policy: Some(SwarmVerificationPolicy::Blocking),
        retry_budget: Some(0),
        status: StudioArtifactWorkItemStatus::Pending,
    });
    work_items.push(StudioArtifactWorkItem {
        id: "repair".to_string(),
        title: "Repair".to_string(),
        role: StudioArtifactWorkerRole::Repair,
        summary:
            "Patch only cited failures against the canonical artifact when verification blocks."
                .to_string(),
        spawned_from_id: None,
        read_paths: Vec::new(),
        write_paths: repair_write_paths.clone(),
        write_regions: repair_write_regions.clone(),
        lease_requirements: {
            let mut leases = repair_write_paths
                .iter()
                .cloned()
                .map(exclusive_write_lease_for_path)
                .collect::<Vec<_>>();
            leases.extend(
                repair_write_regions
                    .iter()
                    .cloned()
                    .map(exclusive_write_lease_for_region),
            );
            leases
        },
        acceptance_criteria: vec!["Repair must stay bounded to cited failures.".to_string()],
        dependency_ids: vec!["judge".to_string()],
        blocked_on_ids: Vec::new(),
        verification_policy: Some(SwarmVerificationPolicy::Blocking),
        retry_budget: Some(2),
        status: StudioArtifactWorkItemStatus::Pending,
    });

    StudioArtifactSwarmPlan {
        version: 1,
        strategy: strategy.to_string(),
        execution_domain: "studio_artifact".to_string(),
        adapter_label: adapter_label.to_string(),
        parallelism_mode: "sequential_by_default".to_string(),
        top_level_objective: Some(brief.artifact_thesis.clone()),
        decomposition_hypothesis: Some(if is_micro_swarm {
            "A small known work graph is sufficient; keep decomposition bounded and avoid full adaptive expansion."
                .to_string()
        } else {
            "The request merits a mutable shared-state work graph with bounded worker scopes."
                .to_string()
        }),
        decomposition_type: Some(if request.renderer == StudioRendererKind::HtmlIframe {
            if is_micro_swarm {
                "small_graph_content_decomposition".to_string()
            } else {
                "adaptive_shared_state_content_decomposition".to_string()
            }
        } else if is_micro_swarm {
            "small_graph_functional_decomposition".to_string()
        } else {
            "adaptive_functional_decomposition".to_string()
        }),
        first_frontier_ids: vec!["planner".to_string()],
        spawn_conditions: if is_micro_swarm {
            vec!["Spawn a bounded repair node only if verification fails.".to_string()]
        } else {
            vec![
                "Spawn bounded repair nodes only when verification cites concrete failures."
                    .to_string(),
                "Allow follow-up repair nodes when earlier repair passes leave unresolved obligations."
                    .to_string(),
            ]
        },
        prune_conditions: vec![
            "Prune repair or integration work when the completion invariant is already satisfied."
                .to_string(),
            "Collapse remaining branches when earlier receipts eliminate downstream obligations."
                .to_string(),
        ],
        merge_strategy: Some(if is_micro_swarm {
            "bounded_direct_merge".to_string()
        } else {
            "bounded_shared_state_patch_merge".to_string()
        }),
        verification_strategy: Some("judge_merged_state_then_repair_if_needed".to_string()),
        fallback_collapse_strategy: Some(
            "Collapse to the smallest remaining frontier that can satisfy the completion invariant."
                .to_string(),
        ),
        completion_invariant: Some(crate::execution::ExecutionCompletionInvariant {
            summary: if is_micro_swarm {
                "Complete once the small mandatory graph lands one valid artifact and verification passes."
                    .to_string()
            } else {
                "Complete once the mandatory shared-state graph and verification obligations are satisfied."
                    .to_string()
            },
            status: crate::execution::ExecutionCompletionInvariantStatus::Pending,
            required_work_item_ids: work_items
                .iter()
                .filter(|item| {
                    item.role != StudioArtifactWorkerRole::Repair
                        && !item.id.starts_with("repair-pass-")
                })
                .map(|item| item.id.clone())
                .collect(),
            satisfied_work_item_ids: Vec::new(),
            speculative_work_item_ids: vec!["repair".to_string()],
            pruned_work_item_ids: Vec::new(),
            required_verification_ids: vec![
                "schema-validation".to_string(),
                "render-evaluation".to_string(),
                "acceptance-judge".to_string(),
            ],
            satisfied_verification_ids: Vec::new(),
            required_artifact_paths: Vec::new(),
            remaining_obligations: Vec::new(),
            allows_early_exit: true,
        }),
        work_items,
    }
}

fn parse_studio_artifact_patch_envelope(raw: &str) -> Result<StudioArtifactPatchEnvelope, String> {
    serde_json::from_str::<StudioArtifactPatchEnvelope>(raw)
        .or_else(|_| {
            let sanitized = sanitize_loose_json_string_literals(raw);
            serde_json::from_str::<StudioArtifactPatchEnvelope>(&sanitized)
                .map_err(|error| error.to_string())
        })
        .or_else(|_| {
            let extracted = extract_first_json_object(raw)
                .ok_or_else(|| "Studio swarm worker output missing JSON object.".to_string())?;
            serde_json::from_str::<StudioArtifactPatchEnvelope>(&extracted)
                .map_err(|error| error.to_string())
        })
        .or_else(|_| {
            let extracted = extract_first_json_object(raw)
                .ok_or_else(|| "Studio swarm worker output missing JSON object.".to_string())?;
            let sanitized = sanitize_loose_json_string_literals(&extracted);
            serde_json::from_str::<StudioArtifactPatchEnvelope>(&sanitized)
                .map_err(|error| error.to_string())
        })
        .map_err(|error| format!("Failed to parse Studio swarm patch envelope: {error}"))
}

fn extract_relaxed_json_string_field(raw: &str, field: &str) -> Option<String> {
    let needle = format!("\"{field}\"");
    let start = raw.find(&needle)?;
    let mut index = start + needle.len();
    let bytes = raw.as_bytes();
    while let Some(byte) = bytes.get(index) {
        if !byte.is_ascii_whitespace() {
            break;
        }
        index += 1;
    }
    if bytes.get(index).copied()? != b':' {
        return None;
    }
    index += 1;
    while let Some(byte) = bytes.get(index) {
        if !byte.is_ascii_whitespace() {
            break;
        }
        index += 1;
    }
    if bytes.get(index).copied()? != b'"' {
        return None;
    }
    index += 1;

    let mut encoded = String::new();
    let mut escaped = false;
    for ch in raw[index..].chars() {
        if escaped {
            encoded.push('\\');
            encoded.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                escaped = true;
            }
            '"' => {
                return serde_json::from_str::<String>(&format!("\"{encoded}\"")).ok();
            }
            '\n' => encoded.push_str("\\n"),
            '\r' => encoded.push_str("\\r"),
            _ => encoded.push(ch),
        }
    }

    None
}

fn extract_html_tag_block(raw: &str, tag: &str) -> Option<String> {
    let start_pattern = format!("<{tag}");
    let end_pattern = format!("</{tag}>");
    let start = raw.find(&start_pattern)?;
    if let Some(end) = raw[start..].rfind(&end_pattern) {
        let end_index = start + end + end_pattern.len();
        return Some(raw[start..end_index].trim().to_string());
    }
    let mut block = raw[start..].trim().to_string();
    if !block.ends_with(&end_pattern) {
        block.push('\n');
        block.push_str(&end_pattern);
    }
    Some(block)
}

fn extract_html_document_block(raw: &str) -> Option<String> {
    let start = raw.find("<!DOCTYPE html").or_else(|| raw.find("<html"))?;
    if let Some(end) = raw[start..].rfind("</html>") {
        let end_index = start + end + "</html>".len();
        return Some(raw[start..end_index].trim().to_string());
    }
    let mut block = raw[start..].trim().to_string();
    if !block.contains("</body>") {
        block.push_str("\n</body>");
    }
    if !block.ends_with("</html>") {
        block.push_str("\n</html>");
    }
    Some(block)
}

fn extract_section_like_block(raw: &str) -> Option<String> {
    for tag in ["section", "article", "main", "div"] {
        if let Some(block) = extract_html_tag_block(raw, tag) {
            return Some(block);
        }
    }
    None
}

fn looks_like_css_source(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    trimmed.contains(":root")
        || trimmed.contains("--")
        || trimmed.contains("@media")
        || trimmed.contains('@')
        || (trimmed.contains('{')
            && trimmed.contains('}')
            && trimmed.contains(':')
            && (trimmed.contains('.') || trimmed.contains('#')))
}

fn looks_like_js_source(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return false;
    }
    trimmed.contains("addEventListener")
        || trimmed.contains("querySelector")
        || trimmed.contains("document.")
        || trimmed.contains("window.")
        || trimmed.contains("const ")
        || trimmed.contains("let ")
        || trimmed.contains("function ")
        || trimmed.contains("=>")
}

fn salvage_studio_swarm_patch_envelope(
    request: &StudioOutcomeArtifactRequest,
    work_item: &StudioArtifactWorkItem,
    raw: &str,
) -> Option<StudioArtifactPatchEnvelope> {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return None;
    }

    let decoded_raw = decode_html_transport_escapes(raw);

    let summary = extract_relaxed_json_string_field(raw, "summary");
    let notes = vec!["Recovered the bounded worker change from malformed JSON.".to_string()];

    let infer_repair_region_id = || {
        extract_relaxed_json_string_field(raw, "regionId")
            .and_then(|candidate| {
                work_item
                    .write_regions
                    .iter()
                    .find(|region| html_swarm_region_ids_match(region, &candidate))
                    .cloned()
                    .or_else(|| Some(candidate))
            })
            .or_else(|| {
                let lowered = raw.to_ascii_lowercase();
                if lowered.contains("<script") {
                    work_item
                        .write_regions
                        .iter()
                        .find(|region| html_swarm_region_ids_match(region, "interaction"))
                        .cloned()
                } else if lowered.contains("<style") {
                    work_item
                        .write_regions
                        .iter()
                        .find(|region| html_swarm_region_ids_match(region, "style-system"))
                        .cloned()
                } else {
                    work_item
                        .write_regions
                        .iter()
                        .find(|region| region.starts_with("section:"))
                        .cloned()
                }
            })
            .or_else(|| work_item.write_regions.first().cloned())
    };

    match work_item.role {
        StudioArtifactWorkerRole::Skeleton => {
            let body = extract_relaxed_json_string_field(raw, "body")
                .or_else(|| extract_html_document_block(raw))?;
            Some(StudioArtifactPatchEnvelope {
                summary,
                notes,
                operations: vec![StudioArtifactPatchOperation {
                    kind: StudioArtifactPatchOperationKind::CreateFile,
                    path: "index.html".to_string(),
                    region_id: None,
                    mime: Some("text/html".to_string()),
                    role: Some(StudioArtifactFileRole::Primary),
                    renderable: Some(true),
                    downloadable: Some(true),
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: Some(body),
                }],
            })
        }
        StudioArtifactWorkerRole::SectionContent
        | StudioArtifactWorkerRole::StyleSystem
        | StudioArtifactWorkerRole::Interaction
        | StudioArtifactWorkerRole::Integrator
        | StudioArtifactWorkerRole::Repair => {
            let body = match work_item.role {
                StudioArtifactWorkerRole::SectionContent => {
                    extract_relaxed_json_string_field(raw, "body")
                        .or_else(|| extract_section_like_block(&decoded_raw))
                        .or_else(|| {
                            let trimmed = decoded_raw.trim();
                            (!trimmed.is_empty())
                                .then(|| format!("<section>\n{}\n</section>", trimmed))
                        })?
                }
                StudioArtifactWorkerRole::StyleSystem => {
                    extract_relaxed_json_string_field(raw, "body")
                        .or_else(|| extract_html_tag_block(&decoded_raw, "style"))
                        .or_else(|| {
                            let trimmed = decoded_raw.trim();
                            looks_like_css_source(trimmed)
                                .then(|| format!("<style>\n{}\n</style>", trimmed))
                        })?
                }
                StudioArtifactWorkerRole::Interaction => {
                    extract_relaxed_json_string_field(raw, "body")
                        .or_else(|| extract_html_tag_block(&decoded_raw, "script"))
                        .or_else(|| {
                            let trimmed = decoded_raw.trim();
                            looks_like_js_source(trimmed)
                                .then(|| format!("<script>\n{}\n</script>", trimmed))
                        })?
                }
                StudioArtifactWorkerRole::Integrator => {
                    extract_relaxed_json_string_field(raw, "body")
                        .or_else(|| extract_html_tag_block(&decoded_raw, "script"))
                        .or_else(|| extract_html_tag_block(&decoded_raw, "style"))
                        .or_else(|| extract_section_like_block(&decoded_raw))
                        .or_else(|| {
                            let trimmed = decoded_raw.trim();
                            if looks_like_js_source(trimmed) {
                                Some(format!("<script>\n{}\n</script>", trimmed))
                            } else if looks_like_css_source(trimmed) {
                                Some(format!("<style>\n{}\n</style>", trimmed))
                            } else if !trimmed.is_empty() {
                                Some(format!("<section>\n{}\n</section>", trimmed))
                            } else {
                                None
                            }
                        })?
                }
                StudioArtifactWorkerRole::Repair => extract_relaxed_json_string_field(raw, "body")
                    .or_else(|| extract_html_tag_block(&decoded_raw, "script"))
                    .or_else(|| extract_html_tag_block(&decoded_raw, "style"))
                    .or_else(|| extract_section_like_block(&decoded_raw))
                    .or_else(|| {
                        let trimmed = decoded_raw.trim();
                        if looks_like_js_source(trimmed) {
                            Some(format!("<script>\n{}\n</script>", trimmed))
                        } else if looks_like_css_source(trimmed) {
                            Some(format!("<style>\n{}\n</style>", trimmed))
                        } else if !trimmed.is_empty() {
                            Some(format!("<section>\n{}\n</section>", trimmed))
                        } else {
                            None
                        }
                    })?,
                _ => return None,
            };
            let region_id = if matches!(
                work_item.role,
                StudioArtifactWorkerRole::Integrator | StudioArtifactWorkerRole::Repair
            ) {
                infer_repair_region_id()?
            } else {
                work_item.write_regions.first()?.clone()
            };
            Some(StudioArtifactPatchEnvelope {
                summary,
                notes,
                operations: vec![StudioArtifactPatchOperation {
                    kind: StudioArtifactPatchOperationKind::ReplaceRegion,
                    path: "index.html".to_string(),
                    region_id: Some(region_id),
                    mime: Some("text/html".to_string()),
                    role: Some(StudioArtifactFileRole::Primary),
                    renderable: Some(true),
                    downloadable: Some(true),
                    encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
                    body: Some(body),
                }],
            })
        }
        _ => None,
    }
}

fn sanitize_loose_json_string_literals(raw: &str) -> String {
    let mut sanitized = String::with_capacity(raw.len() + 64);
    let mut in_string = false;
    let mut escaped = false;

    for ch in raw.chars() {
        if in_string {
            match ch {
                '"' if !escaped => {
                    in_string = false;
                    sanitized.push(ch);
                    escaped = false;
                }
                '\\' if !escaped => {
                    sanitized.push(ch);
                    escaped = true;
                }
                '\n' if !escaped => {
                    sanitized.push_str("\\n");
                }
                '\r' if !escaped => {
                    sanitized.push_str("\\r");
                }
                _ => {
                    sanitized.push(ch);
                    escaped = false;
                }
            }
        } else {
            if ch == '"' {
                in_string = true;
            }
            sanitized.push(ch);
        }
    }

    sanitized
}

fn swarm_patch_schema_contract() -> &'static str {
    "Return exactly one JSON object with this camelCase schema:\n{\n  \"summary\": <string | null>,\n  \"notes\": [<string>],\n  \"operations\": [\n    {\n      \"kind\": \"create_file\" | \"replace_file\" | \"replace_region\" | \"delete_file\",\n      \"path\": <string>,\n      \"regionId\": <string | null>,\n      \"mime\": <string | null>,\n      \"role\": null | \"primary\" | \"source\" | \"export\" | \"supporting\",\n      \"renderable\": <boolean | null>,\n      \"downloadable\": <boolean | null>,\n      \"encoding\": null | \"utf8\" | \"base64\",\n      \"body\": <string | null>\n    }\n  ]\n}\nRules:\n1) Output JSON only.\n2) Only touch the allowed paths and regions.\n3) Use replace_region when the work item owns a region, not replace_file.\n4) Preserve strong authored structure outside the assigned scope.\n5) Do not emit placeholder copy, TODO markers, or HTML comments unless they are the required STUDIO_REGION markers in the HTML skeleton worker."
}

fn html_swarm_region_marker_start(region_id: &str) -> String {
    format!("<!-- STUDIO_REGION_START:{region_id} -->")
}

fn html_swarm_region_marker_end(region_id: &str) -> String {
    format!("<!-- STUDIO_REGION_END:{region_id} -->")
}

fn html_swarm_region_id_variants(region_id: &str) -> Vec<String> {
    let mut variants = vec![region_id.to_string()];
    if let Some(stripped) = region_id.strip_prefix("section:") {
        if !stripped.is_empty() && !variants.iter().any(|value| value == stripped) {
            variants.push(stripped.to_string());
        }
    } else if !region_id.is_empty() {
        let prefixed = format!("section:{region_id}");
        if !variants.iter().any(|value| value == &prefixed) {
            variants.push(prefixed);
        }
    }
    variants
}

fn html_swarm_region_ids_match(left: &str, right: &str) -> bool {
    html_swarm_region_id_variants(left).iter().any(|candidate| {
        html_swarm_region_id_variants(right)
            .iter()
            .any(|other| other == candidate)
    })
}

fn html_swarm_region_default_insert_index(body: &str, region_id: &str) -> usize {
    if region_id == "style-system" {
        return body.find("</head>").unwrap_or(0);
    }
    if region_id == "interaction" {
        return body.find("</body>").unwrap_or(body.len());
    }

    body.find("</main>")
        .or_else(|| body.find("</body>"))
        .unwrap_or(body.len())
}

fn ensure_html_swarm_region_marker_pair(body: &str, region_id: &str) -> String {
    for candidate in html_swarm_region_id_variants(region_id) {
        let start_marker = html_swarm_region_marker_start(&candidate);
        let end_marker = html_swarm_region_marker_end(&candidate);
        if body.contains(&start_marker) && body.contains(&end_marker) {
            return body.to_string();
        }
    }

    for candidate in html_swarm_region_id_variants(region_id) {
        let start_marker = html_swarm_region_marker_start(&candidate);
        if let Some(start_index) = body.find(&start_marker) {
            let content_start = start_index + start_marker.len();
            let insert_at = body[content_start..]
                .find("<!-- STUDIO_REGION_START:")
                .map(|offset| content_start + offset)
                .unwrap_or_else(|| html_swarm_region_default_insert_index(body, region_id));
            let mut rebuilt = String::with_capacity(body.len() + candidate.len() + 48);
            rebuilt.push_str(&body[..insert_at]);
            if !rebuilt.ends_with('\n') {
                rebuilt.push('\n');
            }
            rebuilt.push_str(&html_swarm_region_marker_end(&candidate));
            rebuilt.push('\n');
            rebuilt.push_str(&body[insert_at..]);
            return rebuilt;
        }
    }

    let insert_at = html_swarm_region_default_insert_index(body, region_id);
    let mut rebuilt = String::with_capacity(body.len() + region_id.len() * 2 + 64);
    rebuilt.push_str(&body[..insert_at]);
    if !rebuilt.ends_with('\n') {
        rebuilt.push('\n');
    }
    rebuilt.push_str(&html_swarm_region_marker_start(region_id));
    rebuilt.push('\n');
    rebuilt.push_str(&html_swarm_region_marker_end(region_id));
    rebuilt.push('\n');
    rebuilt.push_str(&body[insert_at..]);
    rebuilt
}

fn normalize_html_swarm_skeleton_markers(body: &str, expected_regions: &[String]) -> String {
    expected_regions
        .iter()
        .fold(body.to_string(), |current, region| {
            ensure_html_swarm_region_marker_pair(&current, region)
        })
}

fn decode_html_transport_escapes(body: &str) -> String {
    if !body.contains("\\n")
        && !body.contains("\\r")
        && !body.contains("\\t")
        && !body.contains("\\\"")
        && !body.contains("\\/")
    {
        return body.to_string();
    }

    body.replace("\\r\\n", "\n")
        .replace("\\n", "\n")
        .replace("\\r", "\n")
        .replace("\\t", "\t")
        .replace("\\\"", "\"")
        .replace("\\/", "/")
}

fn unwrap_custom_html_region_wrapper(body: &str, region_id: &str) -> String {
    let trimmed = body.trim();
    let (custom_tag, canonical_tag) = match region_id {
        "style-system" => ("style-system", "style"),
        "interaction" => ("interaction", "script"),
        _ => return trimmed.to_string(),
    };
    let start_pattern = format!("<{custom_tag}");
    let end_pattern = format!("</{custom_tag}>");
    if !trimmed.starts_with(&start_pattern) {
        return trimmed.to_string();
    }

    let Some(open_end) = trimmed.find('>') else {
        return trimmed.to_string();
    };
    let inner_end = trimmed.rfind(&end_pattern).unwrap_or(trimmed.len());
    let mut inner = trimmed[open_end + 1..inner_end].trim().to_string();
    if inner.starts_with("<!--") && inner.ends_with("-->") {
        inner = inner
            .trim_start_matches("<!--")
            .trim_end_matches("-->")
            .trim()
            .to_string();
    }
    format!("<{canonical_tag}>\n{}\n</{canonical_tag}>", inner.trim())
}

fn normalize_html_swarm_region_replacement(region_id: &str, replacement: &str) -> String {
    let decoded = decode_html_transport_escapes(replacement);
    let unwrapped = unwrap_custom_html_region_wrapper(&decoded, region_id);
    let trimmed = unwrapped.trim();
    match region_id {
        "style-system" => {
            if trimmed.starts_with("<style") {
                trimmed.to_string()
            } else {
                format!("<style>\n{}\n</style>", trimmed)
            }
        }
        "interaction" => {
            if trimmed.starts_with("<script") {
                trimmed.to_string()
            } else {
                format!("<script>\n{}\n</script>", trimmed)
            }
        }
        _ => trimmed.to_string(),
    }
}

fn ensure_html_swarm_visible_main_shell(body: &str) -> String {
    if body.contains("<main") {
        return body.to_string();
    }

    let Some(body_start) = body.find("<body") else {
        return body.to_string();
    };
    let Some(open_end_rel) = body[body_start..].find('>') else {
        return body.to_string();
    };
    let content_start = body_start + open_end_rel + 1;
    let script_start = body[content_start..]
        .find("<script")
        .map(|offset| content_start + offset);
    let body_end = body[content_start..]
        .find("</body>")
        .map(|offset| content_start + offset)
        .unwrap_or(body.len());
    let content_end = script_start.unwrap_or(body_end);
    if content_end <= content_start {
        return body.to_string();
    }

    let inner = body[content_start..content_end].trim();
    if inner.is_empty() {
        return body.to_string();
    }

    let mut rebuilt = String::with_capacity(body.len() + 32);
    rebuilt.push_str(&body[..content_start]);
    if !rebuilt.ends_with('\n') {
        rebuilt.push('\n');
    }
    rebuilt.push_str("<main id=\"artifact-main\">\n");
    rebuilt.push_str(inner);
    rebuilt.push_str("\n</main>\n");
    rebuilt.push_str(&body[content_end..]);
    rebuilt
}

fn normalize_html_swarm_document(body: &str) -> String {
    let decoded = decode_html_transport_escapes(body);
    let normalized_wrappers = decoded
        .replace("<style-system>", "<style>")
        .replace("</style-system>", "</style>")
        .replace("<interaction>", "<script>")
        .replace("</interaction>", "</script>");
    ensure_html_swarm_visible_main_shell(&normalized_wrappers)
}

fn replace_html_swarm_region(
    body: &str,
    region_id: &str,
    replacement: &str,
) -> Result<String, String> {
    let normalized_replacement = normalize_html_swarm_region_replacement(region_id, replacement);
    for candidate in html_swarm_region_id_variants(region_id) {
        let start_marker = html_swarm_region_marker_start(&candidate);
        let end_marker = html_swarm_region_marker_end(&candidate);
        let Some(start_index) = body.find(&start_marker) else {
            continue;
        };
        let content_start = start_index + start_marker.len();
        let Some(relative_end_index) = body[content_start..].find(&end_marker) else {
            return Err(format!(
                "Region marker end '{candidate}' is missing from the canonical artifact."
            ));
        };
        let end_index = content_start + relative_end_index;
        let mut rebuilt = String::with_capacity(body.len() + normalized_replacement.len() + 8);
        rebuilt.push_str(&body[..content_start]);
        rebuilt.push('\n');
        rebuilt.push_str(normalized_replacement.trim());
        rebuilt.push('\n');
        rebuilt.push_str(&body[end_index..]);
        return Ok(rebuilt);
    }
    Err(format!(
        "Region marker '{region_id}' is missing from the canonical artifact."
    ))
}

fn strip_html_swarm_region_markers(body: &str) -> String {
    body.lines()
        .filter(|line| {
            let trimmed = line.trim();
            !(trimmed.starts_with("<!-- STUDIO_REGION_START:")
                || trimmed.starts_with("<!-- STUDIO_REGION_END:"))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn studio_swarm_payload_prompt_view(payload: &StudioGeneratedArtifactPayload) -> serde_json::Value {
    json!({
        "summary": payload.summary,
        "notes": payload.notes,
        "files": payload
            .files
            .iter()
            .map(|file| {
                json!({
                    "path": file.path,
                    "mime": file.mime,
                    "role": file.role,
                    "renderable": file.renderable,
                    "downloadable": file.downloadable,
                    "encoding": file.encoding,
                    "body": file.body,
                })
            })
            .collect::<Vec<_>>(),
    })
}

fn studio_swarm_work_item_context(
    work_item: &StudioArtifactWorkItem,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    judge: Option<&StudioArtifactJudgeResult>,
) -> serde_json::Value {
    match work_item.role {
        StudioArtifactWorkerRole::Skeleton => json!({
            "scaffoldFamily": blueprint.map(|value| value.scaffold_family.clone()),
            "narrativeArc": blueprint.map(|value| value.narrative_arc.clone()),
            "sectionPlan": blueprint.map(|value| value.section_plan.clone()).unwrap_or_default(),
        }),
        StudioArtifactWorkerRole::SectionContent => {
            let target_region = work_item.write_regions.first().cloned().unwrap_or_default();
            let target_id = target_region
                .strip_prefix("section:")
                .unwrap_or(target_region.as_str());
            let section = blueprint.and_then(|value| {
                value
                    .section_plan
                    .iter()
                    .find(|section| {
                        section_region_id(section, 0) == target_id || section.id == target_id
                    })
                    .cloned()
            });
            json!({
                "targetRegion": target_region,
                "section": section,
            })
        }
        StudioArtifactWorkerRole::StyleSystem => json!({
            "designTokens": artifact_ir.map(|value| value.design_tokens.clone()).unwrap_or_default(),
            "colorStrategy": blueprint
                .map(|value| value.design_system.color_strategy.clone())
                .unwrap_or_default(),
            "density": blueprint
                .map(|value| value.design_system.density.clone())
                .unwrap_or_default(),
            "judge": judge,
        }),
        StudioArtifactWorkerRole::Interaction => json!({
            "interactionPlan": blueprint.map(|value| value.interaction_plan.clone()).unwrap_or_default(),
            "interactionGraph": artifact_ir.map(|value| value.interaction_graph.clone()).unwrap_or_default(),
            "judge": judge,
        }),
        StudioArtifactWorkerRole::Integrator | StudioArtifactWorkerRole::Repair => json!({
            "sectionPlan": blueprint.map(|value| value.section_plan.clone()).unwrap_or_default(),
            "interactionPlan": blueprint.map(|value| value.interaction_plan.clone()).unwrap_or_default(),
            "judge": judge,
        }),
        _ => json!({}),
    }
}

fn html_swarm_targeted_repair_template_ids(judge: &StudioArtifactJudgeResult) -> Vec<&'static str> {
    let has_any_issue = |needles: &[&str]| {
        judge
            .issue_classes
            .iter()
            .any(|issue| needles.iter().any(|needle| issue == needle))
    };

    let mut template_ids = Vec::new();
    if has_any_issue(&[
        "main_region_missing",
        "alignment_unstable",
        "low_layout_density",
        "evidence_density_low",
        "visual_hierarchy_sparse",
        "incomplete_artifact",
        "missing_visual_evidence",
        "render_timeout",
    ]) {
        template_ids.push("integrator");
    }
    if has_any_issue(&[
        "low_layout_density",
        "alignment_unstable",
        "visual_hierarchy_sparse",
        "missing_visual_evidence",
        "render_timeout",
    ]) {
        template_ids.push("style-system");
    }
    if has_any_issue(&[
        "missing_interactive_states",
        "interaction_change_weak",
        "interaction_missing",
        "interaction_relevance_low",
        "render_timeout",
        "incomplete_artifact",
    ]) {
        template_ids.push("interaction");
    }
    if template_ids.is_empty() {
        template_ids.push("repair");
    }
    template_ids
}

fn studio_swarm_worker_role_directive(
    request: &StudioOutcomeArtifactRequest,
    work_item: &StudioArtifactWorkItem,
) -> String {
    match (request.renderer, work_item.role) {
        (StudioRendererKind::HtmlIframe, StudioArtifactWorkerRole::Skeleton) => format!(
            "Create one self-contained index.html shell for the artifact. The shell must include <main> and these exact region markers once each: {}. Reserve the style-system region in <head> and the interaction region before </body>, but do not author real CSS rules or JavaScript logic in this step because later workers own those regions. Keep the STUDIO_REGION markers in place so later workers can patch them. Do not force a panel grammar unless the brief actually calls for it.",
            work_item
                .write_regions
                .iter()
                .map(|region| format!(
                    "{} ... {}",
                    html_swarm_region_marker_start(region),
                    html_swarm_region_marker_end(region)
                ))
                .collect::<Vec<_>>()
                .join(" | ")
        ),
        (StudioRendererKind::HtmlIframe, StudioArtifactWorkerRole::SectionContent) => {
            let region = work_item.write_regions.first().cloned().unwrap_or_default();
            format!(
                "Replace only region '{region}' with a complete semantic block that fulfills the section purpose, first-paint utility, and request-specific content. Return exactly one replace_region operation for index.html and do not rewrite other regions."
            )
        }
        (StudioRendererKind::HtmlIframe, StudioArtifactWorkerRole::StyleSystem) => {
            "Replace only the style-system region with one <style> block. Favor slate and graphite neutrals, crisp hierarchy, dense readability, and one restrained cool accent family. Do not change copy or structural HTML outside CSS.".to_string()
        }
        (StudioRendererKind::HtmlIframe, StudioArtifactWorkerRole::Interaction) => {
            "Replace only the interaction region with one <script> block that binds authored controls to visible state changes already present in the DOM. Avoid alert(), external libraries, navigation-only controls, or invisible first paint.".to_string()
        }
        (StudioRendererKind::HtmlIframe, StudioArtifactWorkerRole::Integrator) => {
            "Patch only the regions needed to reconcile visual hierarchy, copy seams, and interaction coherence across the merged artifact. Preserve strong sections; do not restart the artifact from scratch.".to_string()
        }
        (StudioRendererKind::HtmlIframe, StudioArtifactWorkerRole::Repair) => {
            "Patch only the cited failures from judging or verification against the current canonical artifact. Preserve strong authored structure and avoid global rewrites when a narrower region patch will solve the problem.".to_string()
        }
        (_, StudioArtifactWorkerRole::Skeleton) => {
            "Produce the initial renderer-native file set once under a bounded patch envelope. Use create_file or replace_file operations only.".to_string()
        }
        (_, StudioArtifactWorkerRole::Repair) => {
            "Patch the current canonical artifact only where the judge or verification cited concrete failures. Preserve working files and strong request-specific content.".to_string()
        }
        (_, StudioArtifactWorkerRole::Integrator) => {
            "Only patch cross-file or cross-section seams that prevent coherence. Skip the work item instead of rewriting the artifact without need.".to_string()
        }
        _ => "Stay strictly inside the assigned scope and return a valid JSON patch envelope.".to_string(),
    }
}

fn studio_patch_operation_kind_label(kind: StudioArtifactPatchOperationKind) -> &'static str {
    match kind {
        StudioArtifactPatchOperationKind::CreateFile => "create_file",
        StudioArtifactPatchOperationKind::ReplaceFile => "replace_file",
        StudioArtifactPatchOperationKind::ReplaceRegion => "replace_region",
        StudioArtifactPatchOperationKind::DeleteFile => "delete_file",
    }
}

fn build_studio_swarm_patch_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    current_payload: &StudioGeneratedArtifactPayload,
    work_item: &StudioArtifactWorkItem,
    worker_context: serde_json::Value,
    runtime_kind: StudioRuntimeProvenanceKind,
    candidate_seed: u64,
) -> Result<serde_json::Value, String> {
    let compact_prompt = request.renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime;
    if compact_prompt {
        let request_focus_text = compact_local_html_materialization_request_text(request);
        let brief_focus_text = compact_local_html_materialization_brief_text(brief);
        let interaction_contract_text = compact_local_html_interaction_contract_text(brief);
        let selected_skills_json = serialize_materialization_prompt_json(
            &compact_local_html_swarm_skill_focus(selected_skills),
            "Selected skill guidance",
            true,
        )?;
        let retrieved_exemplars_json = serialize_materialization_prompt_json(
            &compact_local_html_swarm_exemplar_focus(retrieved_exemplars),
            "Retrieved exemplars",
            true,
        )?;
        let refinement_json = serialize_materialization_prompt_json(
            &compact_local_html_refinement_context_focus(refinement),
            "Refinement context",
            true,
        )?;
        let current_json = serialize_materialization_prompt_json(
            &compact_local_html_swarm_payload_focus(current_payload, work_item),
            "Current canonical artifact",
            true,
        )?;
        let work_item_json = serialize_materialization_prompt_json(
            &compact_local_html_swarm_work_item_focus(work_item),
            "Swarm work item",
            true,
        )?;
        let worker_context_json = serialize_materialization_prompt_json(
            &compact_local_html_swarm_worker_context_focus(work_item, &worker_context),
            "Worker context",
            true,
        )?;
        let renderer_guidance = compact_local_html_swarm_renderer_guidance(
            request,
            brief,
            work_item,
            candidate_seed,
            runtime_kind,
        );
        let role_directive = studio_swarm_worker_role_directive(request, work_item);
        return Ok(json!([
            {
                "role": "system",
                "content": format!(
                    "You are Studio's typed swarm {:?} worker. Return JSON only. You own only the explicit work item scope and must preserve authored structure outside it.",
                    work_item.role
                )
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus:\n{}\n\nArtifact brief focus:\n{}\n\nInteraction contract:\n{}\n\nSelected skill guidance JSON:\n{}\n\nRetrieved exemplars JSON:\n{}\n\nRefinement context JSON:\n{}\n\nCurrent artifact focus JSON:\n{}\n\nSwarm work item JSON:\n{}\n\nWorker context JSON:\n{}\n\nRole directive:\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
                    title,
                    intent,
                    request_focus_text,
                    brief_focus_text,
                    interaction_contract_text,
                    if matches!(
                        work_item.role,
                        StudioArtifactWorkerRole::Skeleton
                            | StudioArtifactWorkerRole::SectionContent
                            | StudioArtifactWorkerRole::StyleSystem
                            | StudioArtifactWorkerRole::Interaction
                            | StudioArtifactWorkerRole::Repair
                    ) {
                        "[]".to_string()
                    } else {
                        selected_skills_json
                    },
                    if matches!(work_item.role, StudioArtifactWorkerRole::Integrator) {
                        retrieved_exemplars_json
                    } else {
                        "[]".to_string()
                    },
                    refinement_json,
                    current_json,
                    work_item_json,
                    worker_context_json,
                    role_directive,
                    renderer_guidance,
                    swarm_patch_schema_contract(),
                )
            }
        ]));
    }

    let request_json =
        serialize_materialization_prompt_json(request, "Studio artifact request", compact_prompt)?;
    let brief_json =
        serialize_materialization_prompt_json(brief, "Studio artifact brief", compact_prompt)?;
    let blueprint_json = serialize_materialization_prompt_json(
        &blueprint,
        "Studio artifact blueprint",
        compact_prompt,
    )?;
    let artifact_ir_json =
        serialize_materialization_prompt_json(&artifact_ir, "Studio artifact IR", compact_prompt)?;
    let selected_skills_json = serialize_materialization_prompt_json(
        &selected_skills,
        "Selected skill guidance",
        compact_prompt,
    )?;
    let retrieved_exemplars_json = serialize_materialization_prompt_json(
        &retrieved_exemplars,
        "Retrieved exemplars",
        compact_prompt,
    )?;
    let edit_intent_json = serialize_materialization_prompt_json(
        &edit_intent,
        "Studio artifact edit intent",
        compact_prompt,
    )?;
    let refinement_json = serialize_materialization_prompt_json(
        &compact_local_html_refinement_context_focus(refinement),
        "Refinement context",
        compact_prompt,
    )?;
    let current_json = serialize_materialization_prompt_json(
        &studio_swarm_payload_prompt_view(current_payload),
        "Current canonical artifact",
        false,
    )?;
    let work_item_json =
        serialize_materialization_prompt_json(work_item, "Swarm work item", false)?;
    let worker_context_json =
        serialize_materialization_prompt_json(&worker_context, "Worker context", false)?;
    let interaction_contract_json = serialize_materialization_prompt_json(
        &super::studio_artifact_interaction_contract(brief),
        "Interaction contract",
        compact_prompt,
    )?;
    let renderer_guidance = studio_artifact_renderer_authoring_guidance_for_runtime(
        request,
        brief,
        candidate_seed,
        runtime_kind,
    );
    let role_directive = studio_swarm_worker_role_directive(request, work_item);
    Ok(json!([
        {
            "role": "system",
            "content": format!(
                "You are Studio's typed swarm {:?} worker. Return JSON only. You do not own the full artifact. You own only the explicit work item scope and must preserve strong authored structure outside it.",
                work_item.role
            )
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\n{}\n\nRole directive:\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}\n",
                title,
                intent,
                request_json,
                brief_json,
                blueprint_json,
                artifact_ir_json,
                selected_skills_json,
                retrieved_exemplars_json,
                edit_intent_json,
                refinement_json,
                interaction_contract_json,
                current_json,
                role_directive,
                renderer_guidance,
                format!(
                    "{}\n\n{}\n\n{}",
                    work_item_json,
                    worker_context_json,
                    swarm_patch_schema_contract()
                ),
            )
        }
    ]))
}

fn studio_swarm_worker_temperature(
    request: &StudioOutcomeArtifactRequest,
    role: StudioArtifactWorkerRole,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> f32 {
    let (_, configured_temperature, _) =
        candidate_generation_config(request.renderer, runtime_kind);
    let base = effective_candidate_generation_temperature(
        request.renderer,
        runtime_kind,
        configured_temperature,
    );
    match role {
        StudioArtifactWorkerRole::Skeleton | StudioArtifactWorkerRole::SectionContent => base,
        StudioArtifactWorkerRole::StyleSystem | StudioArtifactWorkerRole::Interaction => {
            base.min(0.32)
        }
        StudioArtifactWorkerRole::Integrator => base.min(0.26),
        StudioArtifactWorkerRole::Repair => 0.18,
        _ => 0.0,
    }
}

fn studio_swarm_worker_max_tokens(
    request: &StudioOutcomeArtifactRequest,
    role: StudioArtifactWorkerRole,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> u32 {
    let base = materialization_max_tokens_for_runtime(request.renderer, runtime_kind);
    if request.renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        return match role {
            StudioArtifactWorkerRole::Skeleton => base.min(850),
            StudioArtifactWorkerRole::SectionContent => base.min(1000),
            StudioArtifactWorkerRole::StyleSystem => base.min(1800),
            StudioArtifactWorkerRole::Interaction => base.min(1600),
            StudioArtifactWorkerRole::Integrator => base.min(1800),
            StudioArtifactWorkerRole::Repair => base.min(2200),
            _ => base.min(1200),
        };
    }
    base
}

fn studio_swarm_worker_timeout(
    request: &StudioOutcomeArtifactRequest,
    role: StudioArtifactWorkerRole,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Option<Duration> {
    if request.renderer == StudioRendererKind::HtmlIframe
        && runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        return Some(match role {
            StudioArtifactWorkerRole::Skeleton => Duration::from_secs(120),
            StudioArtifactWorkerRole::SectionContent => Duration::from_secs(150),
            StudioArtifactWorkerRole::StyleSystem => Duration::from_secs(150),
            StudioArtifactWorkerRole::Interaction => Duration::from_secs(150),
            StudioArtifactWorkerRole::Integrator => Duration::from_secs(120),
            StudioArtifactWorkerRole::Repair => Duration::from_secs(180),
            _ => Duration::from_secs(60),
        });
    }
    None
}

fn configured_local_html_swarm_parallelism_cap() -> Option<usize> {
    [
        "AUTOPILOT_STUDIO_SWARM_LOCAL_PARALLELISM_CAP",
        "IOI_STUDIO_SWARM_LOCAL_PARALLELISM_CAP",
        "OLLAMA_NUM_PARALLEL",
    ]
    .iter()
    .find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .filter(|value| *value > 0)
    })
    .map(|value| value.clamp(1, 2))
}

fn studio_swarm_dispatch_parallelism_cap(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> usize {
    match (request.renderer, runtime_kind) {
        (StudioRendererKind::HtmlIframe, StudioRuntimeProvenanceKind::RealRemoteModelRuntime) => 3,
        (StudioRendererKind::HtmlIframe, StudioRuntimeProvenanceKind::RealLocalRuntime) => {
            configured_local_html_swarm_parallelism_cap().unwrap_or(2)
        }
        (StudioRendererKind::HtmlIframe, _) => 2,
        _ => 1,
    }
}

fn studio_swarm_planned_token_budget(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
    swarm_plan: &StudioArtifactSwarmPlan,
) -> u32 {
    swarm_plan
        .work_items
        .iter()
        .map(|item| studio_swarm_worker_max_tokens(request, item.role, runtime_kind))
        .sum()
}

fn build_studio_swarm_patch_repair_prompt(
    work_item: &StudioArtifactWorkItem,
    raw_output: &str,
    parse_error: &str,
) -> serde_json::Value {
    json!([
        {
            "role": "system",
            "content": "You repair malformed Studio swarm worker output into valid JSON. Return JSON only. Preserve the worker's intent, stay inside the existing scope, and do not invent extra files or extra operations. Prefer complete, closed CSS/JS blocks over partial truncation, and preserve every scoped operation you can recover."
        },
        {
            "role": "user",
            "content": format!(
                "Worker id: {}\nWorker role: {:?}\nParse error: {}\n\nMalformed worker output:\n{}\n\nRepair it into one valid JSON object matching this schema exactly:\n{}",
                work_item.id,
                work_item.role,
                parse_error,
                truncate_materialization_focus_text(raw_output, 3200),
                swarm_patch_schema_contract(),
            )
        }
    ])
}

async fn repair_studio_swarm_patch_envelope(
    runtime: Arc<dyn InferenceRuntime>,
    request: &StudioOutcomeArtifactRequest,
    work_item: &StudioArtifactWorkItem,
    raw_output: &str,
    parse_error: &str,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<StudioArtifactPatchEnvelope, String> {
    if let Some(envelope) = salvage_studio_swarm_patch_envelope(request, work_item, raw_output) {
        studio_generation_trace(format!(
            "artifact_generation:swarm_worker:repair_parse:salvage_ok id={} role={:?}",
            work_item.id, work_item.role
        ));
        return Ok(envelope);
    }

    let prompt = build_studio_swarm_patch_repair_prompt(work_item, raw_output, parse_error);
    let prompt_bytes = serde_json::to_vec(&prompt)
        .map_err(|error| format!("Failed to encode Studio swarm repair prompt: {error}"))?;
    let max_tokens =
        studio_swarm_worker_max_tokens(request, work_item.role, runtime_kind).min(1800);
    studio_generation_trace(format!(
        "artifact_generation:swarm_worker:repair_parse:start id={} role={:?} prompt_bytes={} max_tokens={}",
        work_item.id,
        work_item.role,
        prompt_bytes.len(),
        max_tokens
    ));
    let output = tokio::time::timeout(
        Duration::from_secs(150),
        runtime.execute_inference(
            [0u8; 32],
            &prompt_bytes,
            InferenceOptions {
                temperature: 0.0,
                json_mode: true,
                max_tokens,
                ..Default::default()
            },
        ),
    )
    .await
    .map_err(|_| {
        format!(
            "Studio swarm worker '{}' JSON repair timed out after 150s.",
            work_item.id
        )
    })?
    .map_err(|error| format!("Studio swarm worker JSON repair failed: {error}"))?;
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Studio swarm worker JSON repair utf8 decode failed: {error}"))?;
    let envelope = match parse_studio_artifact_patch_envelope(&raw) {
        Ok(envelope) => envelope,
        Err(error) => {
            studio_generation_trace(format!(
                "artifact_generation:swarm_worker:repair_parse:error id={} role={:?} error={} preview={}",
                work_item.id,
                work_item.role,
                error,
                truncate_materialization_focus_text(&raw.replace('\n', "\\n"), 900)
            ));
            salvage_studio_swarm_patch_envelope(request, work_item, &raw)
                .or_else(|| salvage_studio_swarm_patch_envelope(request, work_item, raw_output))
                .ok_or_else(|| format!("Studio swarm worker JSON repair parse failed: {error}"))?
        }
    };
    studio_generation_trace(format!(
        "artifact_generation:swarm_worker:repair_parse:ok id={} role={:?}",
        work_item.id, work_item.role
    ));
    Ok(envelope)
}

async fn execute_studio_swarm_patch_worker(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    current_payload: &StudioGeneratedArtifactPayload,
    work_item: &StudioArtifactWorkItem,
    worker_context: serde_json::Value,
    candidate_seed: u64,
    live_preview_observer: Option<StudioArtifactLivePreviewObserver>,
) -> Result<(StudioArtifactPatchEnvelope, StudioArtifactWorkerReceipt), String> {
    let started_at = studio_swarm_now_iso();
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    let prompt = build_studio_swarm_patch_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        blueprint,
        artifact_ir,
        selected_skills,
        retrieved_exemplars,
        edit_intent,
        refinement,
        current_payload,
        work_item,
        worker_context,
        runtime_kind,
        candidate_seed,
    )?;
    let prompt_bytes = serde_json::to_vec(&prompt)
        .map_err(|error| format!("Failed to encode Studio swarm worker prompt: {error}"))?;
    let max_tokens = studio_swarm_worker_max_tokens(request, work_item.role, runtime_kind);
    let timeout = studio_swarm_worker_timeout(request, work_item.role, runtime_kind);
    studio_generation_trace(format!(
        "artifact_generation:swarm_worker:start id={} role={:?} prompt_bytes={} max_tokens={} timeout_ms={}",
        work_item.id,
        work_item.role,
        prompt_bytes.len(),
        max_tokens,
        timeout.map(|value| value.as_millis()).unwrap_or(0)
    ));
    let inference_started_at = Instant::now();
    let inference_options = InferenceOptions {
        temperature: studio_swarm_worker_temperature(request, work_item.role, runtime_kind),
        json_mode: true,
        max_tokens,
        ..Default::default()
    };
    let preview_language = studio_swarm_preview_language(request);
    let preview_id = format!("{}-live-output", work_item.id);
    let preview_label = format!("{} output", work_item.title);
    let (token_stream, stream_collector) = match live_preview_observer.as_ref() {
        Some(observer) => {
            let (token_tx, collector) = spawn_token_stream_preview_collector(
                Some(observer.clone()),
                preview_id.clone(),
                preview_label.clone(),
                Some(work_item.id.clone()),
                Some(work_item.role),
                preview_language.clone(),
            );
            (Some(token_tx), Some(collector))
        }
        None => (None, None),
    };
    let inference = runtime.execute_inference_streaming(
        [0u8; 32],
        &prompt_bytes,
        inference_options,
        token_stream,
    );
    let output = match timeout {
        Some(limit) => match tokio::time::timeout(limit, inference).await {
            Ok(Ok(output)) => output,
            Ok(Err(error)) => {
                studio_generation_trace(format!(
                    "artifact_generation:swarm_worker:error id={} role={:?} error={}",
                    work_item.id, work_item.role, error
                ));
                return Err(format!("Studio swarm worker inference failed: {error}"));
            }
            Err(_) => {
                studio_generation_trace(format!(
                    "artifact_generation:swarm_worker:timeout id={} role={:?} timeout_ms={}",
                    work_item.id,
                    work_item.role,
                    limit.as_millis()
                ));
                return Err(format!(
                    "Studio swarm worker '{}' timed out after {}s.",
                    work_item.id,
                    limit.as_secs()
                ));
            }
        },
        None => inference
            .await
            .map_err(|error| format!("Studio swarm worker inference failed: {error}"))?,
    };
    studio_generation_trace(format!(
        "artifact_generation:swarm_worker:ok id={} role={:?} elapsed_ms={} output_bytes={}",
        work_item.id,
        work_item.role,
        inference_started_at.elapsed().as_millis(),
        output.len()
    ));
    let streamed_preview = finish_token_stream_preview_collector(stream_collector).await;
    let raw = String::from_utf8(output.clone())
        .map_err(|error| format!("Studio swarm worker utf8 decode failed: {error}"))?;
    let output_preview = truncate_candidate_failure_preview(&raw, 2200);
    if let Some(observer) = live_preview_observer.as_ref() {
        observer(studio_swarm_live_preview(
            preview_id,
            if streamed_preview.trim().is_empty() {
                ExecutionLivePreviewKind::WorkerOutput
            } else {
                ExecutionLivePreviewKind::TokenStream
            },
            preview_label,
            Some(work_item.id.clone()),
            Some(work_item.role),
            "completed",
            preview_language.clone(),
            output_preview.clone().unwrap_or_default(),
            true,
        ));
    }
    let envelope = match parse_studio_artifact_patch_envelope(&raw) {
        Ok(envelope) => envelope,
        Err(error) => {
            studio_generation_trace(format!(
                "artifact_generation:swarm_worker:parse_error id={} role={:?} error={} preview={}",
                work_item.id,
                work_item.role,
                error,
                truncate_materialization_focus_text(&raw.replace('\n', "\\n"), 900)
            ));
            if let Some(envelope) = salvage_studio_swarm_patch_envelope(request, work_item, &raw) {
                studio_generation_trace(format!(
                    "artifact_generation:swarm_worker:salvage_ok id={} role={:?}",
                    work_item.id, work_item.role
                ));
                envelope
            } else {
                repair_studio_swarm_patch_envelope(
                    runtime.clone(),
                    request,
                    work_item,
                    &raw,
                    &error,
                    runtime_kind,
                )
                .await?
            }
        }
    };
    let summary = envelope
        .summary
        .clone()
        .unwrap_or_else(|| work_item.summary.clone());
    Ok((
        envelope.clone(),
        StudioArtifactWorkerReceipt {
            work_item_id: work_item.id.clone(),
            role: work_item.role,
            status: StudioArtifactWorkItemStatus::Succeeded,
            result_kind: Some(SwarmWorkerResultKind::Completed),
            summary,
            started_at,
            finished_at: Some(studio_swarm_now_iso()),
            runtime: runtime.studio_runtime_provenance(),
            read_paths: work_item.read_paths.clone(),
            write_paths: work_item.write_paths.clone(),
            write_regions: work_item.write_regions.clone(),
            spawned_work_item_ids: Vec::new(),
            blocked_on_ids: work_item.blocked_on_ids.clone(),
            prompt_bytes: Some(prompt_bytes.len()),
            output_bytes: Some(output.len()),
            output_preview,
            preview_language,
            notes: envelope.notes.clone(),
            failure: None,
        },
    ))
}

fn diff_payloads_to_patch_operations(
    current: &StudioGeneratedArtifactPayload,
    next: &StudioGeneratedArtifactPayload,
) -> Vec<StudioArtifactPatchOperation> {
    let mut operations = Vec::new();
    for file in &next.files {
        let current_file = current
            .files
            .iter()
            .find(|candidate| candidate.path == file.path);
        if current_file.is_none() {
            operations.push(StudioArtifactPatchOperation {
                kind: StudioArtifactPatchOperationKind::CreateFile,
                path: file.path.clone(),
                region_id: None,
                mime: Some(file.mime.clone()),
                role: Some(file.role),
                renderable: Some(file.renderable),
                downloadable: Some(file.downloadable),
                encoding: file.encoding,
                body: Some(file.body.clone()),
            });
            continue;
        }
        let current_file = current_file.expect("checked above");
        if current_file.mime != file.mime
            || current_file.role != file.role
            || current_file.renderable != file.renderable
            || current_file.downloadable != file.downloadable
            || current_file.encoding != file.encoding
            || current_file.body != file.body
        {
            operations.push(StudioArtifactPatchOperation {
                kind: StudioArtifactPatchOperationKind::ReplaceFile,
                path: file.path.clone(),
                region_id: None,
                mime: Some(file.mime.clone()),
                role: Some(file.role),
                renderable: Some(file.renderable),
                downloadable: Some(file.downloadable),
                encoding: file.encoding,
                body: Some(file.body.clone()),
            });
        }
    }
    for file in &current.files {
        if next
            .files
            .iter()
            .all(|candidate| candidate.path != file.path)
        {
            operations.push(StudioArtifactPatchOperation {
                kind: StudioArtifactPatchOperationKind::DeleteFile,
                path: file.path.clone(),
                region_id: None,
                mime: None,
                role: None,
                renderable: None,
                downloadable: None,
                encoding: None,
                body: None,
            });
        }
    }
    operations
}

fn sanitize_swarm_payload_for_validation(
    payload: &StudioGeneratedArtifactPayload,
) -> StudioGeneratedArtifactPayload {
    let mut sanitized = payload.clone();
    for file in &mut sanitized.files {
        if file.mime == "text/html" || file.path.ends_with(".html") {
            file.body = normalize_html_swarm_document(&strip_html_swarm_region_markers(&file.body));
        }
    }
    sanitized
}

fn repair_swarm_primary_file_assignment(
    payload: &StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
) -> StudioGeneratedArtifactPayload {
    let mut repaired = payload.clone();
    let default_file = default_generated_artifact_file_for_renderer(request.renderer);
    if let Some(file) = repaired
        .files
        .iter_mut()
        .find(|file| file.path == default_file.path)
    {
        file.role = default_file.role;
        file.renderable = default_file.renderable;
        file.downloadable = default_file.downloadable;
        if file.encoding.is_none() {
            file.encoding = default_file.encoding;
        }
        return repaired;
    }

    if repaired.files.iter().any(|file| {
        matches!(
            file.role,
            StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
        )
    }) {
        return repaired;
    }

    if let Some(file) = repaired.files.iter_mut().find(|file| file.renderable) {
        file.role = default_file.role;
    }

    repaired
}

pub(crate) fn validate_swarm_generated_artifact_payload(
    payload: &StudioGeneratedArtifactPayload,
    request: &StudioOutcomeArtifactRequest,
) -> Result<StudioGeneratedArtifactPayload, String> {
    let sanitized = sanitize_swarm_payload_for_validation(payload);
    let repaired = repair_swarm_primary_file_assignment(&sanitized, request);
    if let Err(error) = super::validate_generated_artifact_payload(&repaired, request) {
        if request.renderer == StudioRendererKind::HtmlIframe
            && studio_swarm_soft_validation_error(&error)
        {
            return Ok(repaired);
        }
        return Err(error);
    }
    Ok(repaired)
}

pub type StudioArtifactGenerationProgressObserver =
    Arc<dyn Fn(StudioArtifactGenerationProgress) + Send + Sync>;
type StudioArtifactLivePreviewObserver = Arc<dyn Fn(ExecutionLivePreview) + Send + Sync>;

struct StudioTokenStreamPreviewCollector {
    receiver_task: JoinHandle<String>,
    emitter_task: JoinHandle<()>,
}

fn studio_swarm_progress_step(
    swarm_execution: &StudioArtifactSwarmExecutionSummary,
    summary: impl Into<String>,
) -> String {
    format!(
        "{} Swarm is at {}/{} completed work items.",
        summary.into(),
        swarm_execution.completed_work_items,
        swarm_execution.total_work_items
    )
}

fn studio_swarm_preview_language(request: &StudioOutcomeArtifactRequest) -> Option<String> {
    let language = match request.renderer {
        StudioRendererKind::HtmlIframe => "html",
        StudioRendererKind::Markdown => "markdown",
        StudioRendererKind::JsxSandbox | StudioRendererKind::WorkspaceSurface => "tsx",
        StudioRendererKind::Svg => "svg",
        StudioRendererKind::Mermaid => "mermaid",
        StudioRendererKind::PdfEmbed => "text",
        StudioRendererKind::BundleManifest | StudioRendererKind::DownloadCard => "json",
    };
    Some(language.to_string())
}

fn studio_swarm_live_preview(
    id: impl Into<String>,
    kind: ExecutionLivePreviewKind,
    label: impl Into<String>,
    work_item_id: Option<String>,
    role: Option<StudioArtifactWorkerRole>,
    status: impl Into<String>,
    language: Option<String>,
    content: impl Into<String>,
    is_final: bool,
) -> ExecutionLivePreview {
    ExecutionLivePreview {
        id: id.into(),
        kind,
        label: label.into(),
        work_item_id,
        role,
        status: status.into(),
        language,
        content: content.into(),
        is_final,
        updated_at: studio_swarm_now_iso(),
    }
}

fn spawn_token_stream_preview_collector(
    observer: Option<StudioArtifactLivePreviewObserver>,
    preview_id: String,
    preview_label: String,
    work_item_id: Option<String>,
    role: Option<StudioArtifactWorkerRole>,
    language: Option<String>,
) -> (mpsc::Sender<String>, StudioTokenStreamPreviewCollector) {
    let (token_tx, mut token_rx) = mpsc::channel::<String>(256);
    let combined_state = Arc::new(Mutex::new(String::new()));
    let stream_closed = Arc::new(AtomicBool::new(false));

    let receiver_state = combined_state.clone();
    let receiver_closed = stream_closed.clone();
    let receiver_task = tokio::spawn(async move {
        while let Some(chunk) = token_rx.recv().await {
            if chunk.is_empty() {
                continue;
            }
            if let Ok(mut combined) = receiver_state.lock() {
                combined.push_str(&chunk);
            }
        }
        receiver_closed.store(true, Ordering::SeqCst);
        receiver_state
            .lock()
            .map(|combined| combined.clone())
            .unwrap_or_default()
    });

    let emitter_task = match observer {
        Some(observer) => {
            let emitter_state = combined_state.clone();
            let emitter_closed = stream_closed.clone();
            tokio::spawn(async move {
                let mut last_emitted = String::new();
                let mut ticker = tokio::time::interval(Duration::from_millis(180));
                ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

                loop {
                    ticker.tick().await;
                    let snapshot = emitter_state
                        .lock()
                        .map(|combined| combined.clone())
                        .unwrap_or_default();
                    if !snapshot.trim().is_empty() && snapshot != last_emitted {
                        observer(studio_swarm_live_preview(
                            preview_id.clone(),
                            ExecutionLivePreviewKind::TokenStream,
                            preview_label.clone(),
                            work_item_id.clone(),
                            role,
                            "streaming",
                            language.clone(),
                            live_token_stream_preview_text(&snapshot, 2200),
                            false,
                        ));
                        last_emitted = snapshot;
                    }

                    if emitter_closed.load(Ordering::SeqCst) {
                        let final_snapshot = emitter_state
                            .lock()
                            .map(|combined| combined.clone())
                            .unwrap_or_default();
                        if final_snapshot.trim().is_empty() || final_snapshot == last_emitted {
                            break;
                        }
                    }
                }
            })
        }
        None => tokio::spawn(async {}),
    };

    (
        token_tx,
        StudioTokenStreamPreviewCollector {
            receiver_task,
            emitter_task,
        },
    )
}

async fn finish_token_stream_preview_collector(
    collector: Option<StudioTokenStreamPreviewCollector>,
) -> String {
    let Some(collector) = collector else {
        return String::new();
    };
    let combined = collector.receiver_task.await.unwrap_or_default();
    let _ = collector.emitter_task.await;
    combined
}

fn upsert_execution_live_preview(
    previews: &mut Vec<ExecutionLivePreview>,
    preview: ExecutionLivePreview,
) {
    if let Some(existing) = previews.iter_mut().find(|entry| entry.id == preview.id) {
        *existing = preview;
        return;
    }
    previews.push(preview);
}

fn snapshot_execution_live_previews(
    live_preview_state: &Arc<Mutex<Vec<ExecutionLivePreview>>>,
) -> Vec<ExecutionLivePreview> {
    live_preview_state
        .lock()
        .map(|guard| guard.clone())
        .unwrap_or_default()
}

fn summarize_patch_preview(operations: &[StudioArtifactPatchOperation]) -> Option<String> {
    let preview_body = operations.iter().find_map(|operation| {
        operation
            .body
            .as_ref()
            .map(|body| truncate_materialization_focus_text(body, 900))
            .filter(|body| !body.is_empty())
    })?;
    Some(preview_body)
}

fn studio_swarm_canonical_preview(
    payload: &StudioGeneratedArtifactPayload,
    work_item_id: Option<String>,
    work_item_role: Option<StudioArtifactWorkerRole>,
    status: &str,
    is_final: bool,
) -> Option<ExecutionLivePreview> {
    let preview_file = payload
        .files
        .iter()
        .find(|file| {
            (file.path.ends_with(".html") || file.mime == "text/html")
                && !file.body.trim().is_empty()
        })
        .or_else(|| {
            payload
                .files
                .iter()
                .find(|file| !file.body.trim().is_empty())
        })?;
    Some(studio_swarm_live_preview(
        "canonical-artifact-preview".to_string(),
        ExecutionLivePreviewKind::ChangePreview,
        format!("Live artifact code · {}", preview_file.path),
        work_item_id,
        work_item_role,
        status,
        Some(preview_file.mime.clone()),
        truncate_materialization_focus_text(&preview_file.body, 2200),
        is_final,
    ))
}

fn studio_swarm_partial_budget_summary(
    request: &StudioOutcomeArtifactRequest,
    production_provenance: StudioRuntimeProvenanceKind,
    swarm_plan: &StudioArtifactSwarmPlan,
    worker_receipts: &[StudioArtifactWorkerReceipt],
) -> ExecutionBudgetSummary {
    let dispatched_worker_count = worker_receipts
        .iter()
        .filter(|receipt| {
            !matches!(
                receipt.result_kind,
                Some(SwarmWorkerResultKind::Noop) | Some(SwarmWorkerResultKind::Blocked)
            )
        })
        .count();
    let conflict_count = worker_receipts
        .iter()
        .filter(|receipt| matches!(receipt.result_kind, Some(SwarmWorkerResultKind::Conflict)))
        .count();
    ExecutionBudgetSummary {
        planned_worker_count: Some(swarm_plan.work_items.len()),
        dispatched_worker_count: Some(dispatched_worker_count),
        token_budget: Some(studio_swarm_planned_token_budget(
            request,
            production_provenance,
            swarm_plan,
        )),
        token_usage: None,
        wall_clock_ms: None,
        coordination_overhead_ms: None,
        status: if conflict_count > 0 {
            "conflicted".to_string()
        } else if dispatched_worker_count > 0 {
            "running".to_string()
        } else {
            "planned".to_string()
        },
    }
}

fn non_swarm_required_artifact_paths(payload: &StudioGeneratedArtifactPayload) -> Vec<String> {
    let mut paths = payload
        .files
        .iter()
        .filter(|file| {
            file.renderable
                || matches!(
                    file.role,
                    StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
                )
        })
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    if paths.is_empty() {
        paths = payload
            .files
            .iter()
            .filter(|file| !file.body.trim().is_empty())
            .map(|file| file.path.clone())
            .collect();
    }
    paths.sort();
    paths.dedup();
    paths
}

fn non_swarm_canonical_preview(
    request: &StudioOutcomeArtifactRequest,
    payload: &StudioGeneratedArtifactPayload,
    status: &str,
    is_final: bool,
) -> Option<ExecutionLivePreview> {
    let preview_file = payload
        .files
        .iter()
        .find(|file| {
            matches!(
                file.role,
                StudioArtifactFileRole::Primary | StudioArtifactFileRole::Export
            ) && !file.body.trim().is_empty()
        })
        .or_else(|| {
            payload
                .files
                .iter()
                .find(|file| !file.body.trim().is_empty())
        })?;
    Some(studio_swarm_live_preview(
        "canonical-artifact-preview".to_string(),
        ExecutionLivePreviewKind::ChangePreview,
        format!("Live artifact code · {}", preview_file.path),
        None,
        None,
        status,
        studio_swarm_preview_language(request),
        truncate_materialization_focus_text(&preview_file.body, 2200),
        is_final,
    ))
}

fn build_non_swarm_execution_envelope(
    request: &StudioOutcomeArtifactRequest,
    execution_strategy: StudioExecutionStrategy,
    live_previews: &[ExecutionLivePreview],
    invariant_status: ExecutionCompletionInvariantStatus,
    required_artifact_paths: Vec<String>,
) -> Option<ExecutionEnvelope> {
    let mut execution_envelope = build_execution_envelope_from_swarm(
        Some(execution_strategy),
        Some("studio_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        None,
        None,
        &[],
        &[],
        &[],
        &[],
    );
    annotate_execution_envelope(
        &mut execution_envelope,
        Some(derive_execution_mode_decision(
            StudioOutcomeKind::Artifact,
            Some(request),
            execution_strategy,
            1.0,
            false,
            false,
        )),
        Some(completion_invariant_for_direct_execution(
            execution_strategy,
            required_artifact_paths,
            vec!["verify".to_string()],
            invariant_status,
        )),
    );
    if let Some(envelope) = execution_envelope.as_mut() {
        envelope.live_previews = live_previews.to_vec();
    }
    execution_envelope
}

fn emit_non_swarm_generation_progress(
    observer: Option<&StudioArtifactGenerationProgressObserver>,
    request: &StudioOutcomeArtifactRequest,
    execution_strategy: StudioExecutionStrategy,
    live_previews: &[ExecutionLivePreview],
    current_step: impl Into<String>,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
    judge: Option<&StudioArtifactJudgeResult>,
    invariant_status: ExecutionCompletionInvariantStatus,
    required_artifact_paths: Vec<String>,
) {
    let Some(observer) = observer else {
        return;
    };

    observer(StudioArtifactGenerationProgress {
        current_step: current_step.into(),
        execution_envelope: build_non_swarm_execution_envelope(
            request,
            execution_strategy,
            live_previews,
            invariant_status,
            required_artifact_paths,
        ),
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        render_evaluation: render_evaluation.cloned(),
        judge: judge.cloned(),
    });
}

fn emit_studio_swarm_generation_progress(
    observer: Option<&StudioArtifactGenerationProgressObserver>,
    request: &StudioOutcomeArtifactRequest,
    production_provenance: StudioRuntimeProvenanceKind,
    swarm_plan: &StudioArtifactSwarmPlan,
    worker_receipts: &[StudioArtifactWorkerReceipt],
    patch_receipts: &[StudioArtifactPatchReceipt],
    merge_receipts: &[StudioArtifactMergeReceipt],
    verification_receipts: &[StudioArtifactVerificationReceipt],
    graph_mutation_receipts: &[ExecutionGraphMutationReceipt],
    runtime_dispatch_batches: &[ExecutionDispatchBatch],
    repair_receipts: &[ExecutionRepairReceipt],
    replan_receipts: &[ExecutionReplanReceipt],
    live_previews: &[ExecutionLivePreview],
    current_stage: &str,
    active_worker_role: Option<StudioArtifactWorkerRole>,
    verification_status: &str,
    current_step: impl Into<String>,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
    judge: Option<&StudioArtifactJudgeResult>,
) {
    let Some(observer) = observer else {
        return;
    };

    let swarm_execution = studio_swarm_execution_summary(
        swarm_plan,
        current_stage,
        active_worker_role,
        verification_status,
    );
    let execution_envelope = build_execution_envelope_from_swarm_with_receipts(
        None,
        Some("studio_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        Some(swarm_plan),
        Some(&swarm_execution),
        worker_receipts,
        patch_receipts,
        merge_receipts,
        verification_receipts,
        graph_mutation_receipts,
        runtime_dispatch_batches,
        repair_receipts,
        replan_receipts,
        Some(studio_swarm_partial_budget_summary(
            request,
            production_provenance,
            swarm_plan,
            worker_receipts,
        )),
        live_previews,
    );

    observer(StudioArtifactGenerationProgress {
        current_step: current_step.into(),
        execution_envelope,
        swarm_plan: Some(swarm_plan.clone()),
        swarm_execution: Some(swarm_execution),
        swarm_worker_receipts: worker_receipts.to_vec(),
        swarm_change_receipts: patch_receipts.to_vec(),
        swarm_merge_receipts: merge_receipts.to_vec(),
        swarm_verification_receipts: verification_receipts.to_vec(),
        render_evaluation: render_evaluation.cloned(),
        judge: judge.cloned(),
    });
}

fn ensure_swarm_file_from_operation(
    request: &StudioOutcomeArtifactRequest,
    operation: &StudioArtifactPatchOperation,
) -> Result<StudioGeneratedArtifactFile, String> {
    let mut file = default_generated_artifact_file_for_renderer(request.renderer);
    file.path = operation.path.clone();
    if let Some(mime) = operation.mime.as_ref() {
        file.mime = mime.clone();
    }
    if let Some(role) = operation.role {
        file.role = role;
    }
    if let Some(renderable) = operation.renderable {
        file.renderable = renderable;
    }
    if let Some(downloadable) = operation.downloadable {
        file.downloadable = downloadable;
    }
    if let Some(encoding) = operation.encoding {
        file.encoding = Some(encoding);
    }
    file.body = operation.body.clone().ok_or_else(|| {
        format!(
            "Patch operation for '{}' is missing a body.",
            operation.path
        )
    })?;
    Ok(file)
}

fn studio_swarm_rejected_patch_receipts(
    work_item: &StudioArtifactWorkItem,
    summary: impl Into<String>,
    operation_kinds: Vec<String>,
    touched_paths: Vec<String>,
    touched_regions: Vec<String>,
    failure: impl Into<String>,
) -> (StudioArtifactPatchReceipt, StudioArtifactMergeReceipt) {
    let summary = summary.into();
    let failure = failure.into();
    (
        StudioArtifactPatchReceipt {
            work_item_id: work_item.id.clone(),
            status: StudioArtifactWorkItemStatus::Rejected,
            summary: summary.clone(),
            operation_count: operation_kinds.len(),
            touched_paths: touched_paths.clone(),
            touched_regions: touched_regions.clone(),
            operation_kinds,
            preview: None,
            preview_language: None,
            failure: Some(failure.clone()),
        },
        StudioArtifactMergeReceipt {
            work_item_id: work_item.id.clone(),
            status: StudioArtifactWorkItemStatus::Rejected,
            summary,
            applied_operation_count: 0,
            touched_paths,
            touched_regions,
            rejected_reason: Some(failure),
        },
    )
}

fn html_swarm_patch_contains_region_markers(body: &str) -> bool {
    body.lines().any(|line| {
        let trimmed = line.trim();
        trimmed.starts_with("<!-- STUDIO_REGION_START:")
            || trimmed.starts_with("<!-- STUDIO_REGION_END:")
    })
}

fn normalize_region_owned_html_body_for_role(role: StudioArtifactWorkerRole, body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.is_empty() {
        return body.to_string();
    }

    match role {
        StudioArtifactWorkerRole::StyleSystem => {
            if trimmed.to_ascii_lowercase().contains("<style") {
                body.to_string()
            } else {
                format!("<style>\n{}\n</style>", trimmed)
            }
        }
        StudioArtifactWorkerRole::Interaction => {
            if trimmed.to_ascii_lowercase().contains("<script") {
                body.to_string()
            } else {
                format!("<script>\n{}\n</script>", trimmed)
            }
        }
        StudioArtifactWorkerRole::SectionContent => {
            if trimmed.starts_with('<') {
                body.to_string()
            } else {
                format!("<section>\n{}\n</section>", trimmed)
            }
        }
        _ => body.to_string(),
    }
}

fn studio_swarm_semantic_conflict_reason(
    request: &StudioOutcomeArtifactRequest,
    work_item: &StudioArtifactWorkItem,
    operation: &StudioArtifactPatchOperation,
) -> Option<String> {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return None;
    }
    let body = operation.body.as_deref().unwrap_or_default();
    let lowered = body.to_ascii_lowercase();

    if matches!(
        operation.kind,
        StudioArtifactPatchOperationKind::ReplaceRegion
    ) && work_item.role != StudioArtifactWorkerRole::Skeleton
        && html_swarm_patch_contains_region_markers(body)
    {
        return Some(format!(
            "Work item '{}' attempted to inject nested swarm region markers into '{}'.",
            work_item.id,
            operation.region_id.as_deref().unwrap_or("unknown-region")
        ));
    }

    match work_item.role {
        StudioArtifactWorkerRole::SectionContent => {
            if lowered.contains("<script") || lowered.contains("<style") {
                return Some(format!(
                    "Section worker '{}' crossed a semantic ownership boundary by emitting script/style payloads.",
                    work_item.id
                ));
            }
        }
        StudioArtifactWorkerRole::StyleSystem => {
            if lowered.contains("<script") {
                return Some(format!(
                    "Style worker '{}' crossed a semantic ownership boundary by emitting script payloads.",
                    work_item.id
                ));
            }
        }
        StudioArtifactWorkerRole::Interaction => {
            if lowered.contains("<style") {
                return Some(format!(
                    "Interaction worker '{}' crossed a semantic ownership boundary by emitting style payloads.",
                    work_item.id
                ));
            }
        }
        _ => {}
    }

    None
}

fn studio_swarm_skip_receipt(
    work_item: &StudioArtifactWorkItem,
    runtime: &Arc<dyn InferenceRuntime>,
    summary: impl Into<String>,
) -> StudioArtifactWorkerReceipt {
    let summary = summary.into();
    StudioArtifactWorkerReceipt {
        work_item_id: work_item.id.clone(),
        role: work_item.role,
        status: StudioArtifactWorkItemStatus::Skipped,
        result_kind: Some(SwarmWorkerResultKind::Noop),
        summary,
        started_at: studio_swarm_now_iso(),
        finished_at: Some(studio_swarm_now_iso()),
        runtime: runtime.studio_runtime_provenance(),
        read_paths: work_item.read_paths.clone(),
        write_paths: work_item.write_paths.clone(),
        write_regions: work_item.write_regions.clone(),
        spawned_work_item_ids: Vec::new(),
        blocked_on_ids: work_item.blocked_on_ids.clone(),
        prompt_bytes: None,
        output_bytes: None,
        output_preview: None,
        preview_language: None,
        notes: Vec::new(),
        failure: None,
    }
}

fn studio_swarm_skip_summary_for_html_work_item(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    production_provenance: StudioRuntimeProvenanceKind,
    work_item: &StudioArtifactWorkItem,
) -> Option<String> {
    if request.renderer != StudioRendererKind::HtmlIframe {
        return None;
    }

    if work_item.role == StudioArtifactWorkerRole::Interaction
        && brief.required_interactions.is_empty()
        && blueprint.is_none_or(|value| value.interaction_plan.is_empty())
    {
        return Some(
            "The HTML artifact did not require a dedicated interaction patch.".to_string(),
        );
    }

    if work_item.role == StudioArtifactWorkerRole::Integrator
        && production_provenance == StudioRuntimeProvenanceKind::RealLocalRuntime
    {
        return Some(
            "The merged local HTML artifact now goes straight to judging; keep integrator reserve for targeted repair only."
                .to_string(),
        );
    }

    None
}

pub(crate) fn apply_studio_swarm_patch_envelope(
    request: &StudioOutcomeArtifactRequest,
    payload: &mut StudioGeneratedArtifactPayload,
    work_item: &StudioArtifactWorkItem,
    envelope: &StudioArtifactPatchEnvelope,
) -> Result<(StudioArtifactPatchReceipt, StudioArtifactMergeReceipt), String> {
    let mut touched_paths = Vec::new();
    let mut touched_regions = Vec::new();
    let mut operation_kinds = Vec::new();
    for operation in &envelope.operations {
        let normalized_operation = if work_item.role != StudioArtifactWorkerRole::Skeleton
            && !work_item.write_regions.is_empty()
            && !matches!(
                operation.kind,
                StudioArtifactPatchOperationKind::ReplaceRegion
            ) {
            let region_id = operation
                .region_id
                .clone()
                .or_else(|| work_item.write_regions.first().cloned())
                .ok_or_else(|| {
                    format!(
                        "Work item '{}' emitted a file-scoped patch without a scoped region.",
                        work_item.id
                    )
                })?;
            StudioArtifactPatchOperation {
                kind: StudioArtifactPatchOperationKind::ReplaceRegion,
                path: operation.path.clone(),
                region_id: Some(region_id),
                mime: Some("text/html".to_string()),
                role: Some(StudioArtifactFileRole::Primary),
                renderable: Some(true),
                downloadable: Some(true),
                encoding: operation.encoding,
                body: operation
                    .body
                    .as_deref()
                    .map(|body| normalize_region_owned_html_body_for_role(work_item.role, body)),
            }
        } else {
            operation.clone()
        };

        if !work_item.write_paths.is_empty()
            && !work_item
                .write_paths
                .iter()
                .any(|path| path == &normalized_operation.path)
        {
            return Ok(studio_swarm_rejected_patch_receipts(
                work_item,
                envelope
                    .summary
                    .clone()
                    .unwrap_or_else(|| work_item.summary.clone()),
                vec![studio_patch_operation_kind_label(normalized_operation.kind).to_string()],
                vec![normalized_operation.path.clone()],
                Vec::new(),
                format!(
                    "Work item '{}' attempted to edit out-of-scope path '{}'.",
                    work_item.id, normalized_operation.path
                ),
            ));
        }
        if let Some(reason) =
            studio_swarm_semantic_conflict_reason(request, work_item, &normalized_operation)
        {
            return Ok(studio_swarm_rejected_patch_receipts(
                work_item,
                envelope
                    .summary
                    .clone()
                    .unwrap_or_else(|| work_item.summary.clone()),
                vec![studio_patch_operation_kind_label(normalized_operation.kind).to_string()],
                vec![normalized_operation.path.clone()],
                normalized_operation.region_id.clone().into_iter().collect(),
                reason,
            ));
        }
        if matches!(
            normalized_operation.kind,
            StudioArtifactPatchOperationKind::ReplaceRegion
        ) {
            let Some(region_id) = normalized_operation.region_id.as_ref() else {
                return Ok(studio_swarm_rejected_patch_receipts(
                    work_item,
                    envelope
                        .summary
                        .clone()
                        .unwrap_or_else(|| work_item.summary.clone()),
                    vec![studio_patch_operation_kind_label(normalized_operation.kind).to_string()],
                    vec![normalized_operation.path.clone()],
                    Vec::new(),
                    format!(
                        "Work item '{}' emitted a region patch without regionId.",
                        work_item.id
                    ),
                ));
            };
            let Some(canonical_region) = work_item
                .write_regions
                .iter()
                .find(|region| html_swarm_region_ids_match(region, region_id))
                .cloned()
            else {
                return Ok(studio_swarm_rejected_patch_receipts(
                    work_item,
                    envelope
                        .summary
                        .clone()
                        .unwrap_or_else(|| work_item.summary.clone()),
                    vec![studio_patch_operation_kind_label(normalized_operation.kind).to_string()],
                    vec![normalized_operation.path.clone()],
                    vec![region_id.clone()],
                    format!(
                        "Work item '{}' attempted to edit out-of-scope region '{}'.",
                        work_item.id, region_id
                    ),
                ));
            };
            let Some(file) = payload
                .files
                .iter_mut()
                .find(|file| file.path == normalized_operation.path)
            else {
                return Ok(studio_swarm_rejected_patch_receipts(
                    work_item,
                    envelope
                        .summary
                        .clone()
                        .unwrap_or_else(|| work_item.summary.clone()),
                    vec![studio_patch_operation_kind_label(normalized_operation.kind).to_string()],
                    vec![normalized_operation.path.clone()],
                    vec![canonical_region.clone()],
                    format!(
                        "Work item '{}' attempted to patch missing file '{}'.",
                        work_item.id, normalized_operation.path
                    ),
                ));
            };
            let Some(replacement) = normalized_operation.body.as_ref() else {
                return Ok(studio_swarm_rejected_patch_receipts(
                    work_item,
                    envelope
                        .summary
                        .clone()
                        .unwrap_or_else(|| work_item.summary.clone()),
                    vec![studio_patch_operation_kind_label(normalized_operation.kind).to_string()],
                    vec![normalized_operation.path.clone()],
                    vec![canonical_region.clone()],
                    format!(
                        "Work item '{}' emitted an empty region patch for '{}'.",
                        work_item.id, region_id
                    ),
                ));
            };
            file.body = replace_html_swarm_region(&file.body, &canonical_region, replacement)?;
            touched_regions.push(canonical_region);
        } else {
            match normalized_operation.kind {
                StudioArtifactPatchOperationKind::CreateFile => {
                    let mut file =
                        ensure_swarm_file_from_operation(request, &normalized_operation)?;
                    if work_item.role == StudioArtifactWorkerRole::Skeleton
                        && (file.mime == "text/html" || file.path.ends_with(".html"))
                        && !work_item.write_regions.is_empty()
                    {
                        file.body = normalize_html_swarm_skeleton_markers(
                            &file.body,
                            &work_item.write_regions,
                        );
                    }
                    if let Some(existing) = payload
                        .files
                        .iter_mut()
                        .find(|file| file.path == normalized_operation.path)
                    {
                        *existing = file;
                    } else {
                        payload.files.push(file);
                    }
                }
                StudioArtifactPatchOperationKind::ReplaceFile => {
                    let mut file =
                        ensure_swarm_file_from_operation(request, &normalized_operation)?;
                    if work_item.role == StudioArtifactWorkerRole::Skeleton
                        && (file.mime == "text/html" || file.path.ends_with(".html"))
                        && !work_item.write_regions.is_empty()
                    {
                        file.body = normalize_html_swarm_skeleton_markers(
                            &file.body,
                            &work_item.write_regions,
                        );
                    }
                    let Some(existing) = payload
                        .files
                        .iter_mut()
                        .find(|candidate| candidate.path == normalized_operation.path)
                    else {
                        return Ok(studio_swarm_rejected_patch_receipts(
                            work_item,
                            envelope
                                .summary
                                .clone()
                                .unwrap_or_else(|| work_item.summary.clone()),
                            vec![studio_patch_operation_kind_label(normalized_operation.kind)
                                .to_string()],
                            vec![normalized_operation.path.clone()],
                            Vec::new(),
                            format!(
                                "Work item '{}' attempted to replace missing file '{}'.",
                                work_item.id, normalized_operation.path
                            ),
                        ));
                    };
                    *existing = file;
                }
                StudioArtifactPatchOperationKind::DeleteFile => {
                    payload
                        .files
                        .retain(|file| file.path != normalized_operation.path);
                }
                StudioArtifactPatchOperationKind::ReplaceRegion => {}
            }
        }
        touched_paths.push(normalized_operation.path.clone());
        operation_kinds
            .push(studio_patch_operation_kind_label(normalized_operation.kind).to_string());
    }

    let summary = envelope
        .summary
        .clone()
        .unwrap_or_else(|| work_item.summary.clone());
    Ok((
        StudioArtifactPatchReceipt {
            work_item_id: work_item.id.clone(),
            status: if envelope.operations.is_empty() {
                StudioArtifactWorkItemStatus::Skipped
            } else {
                StudioArtifactWorkItemStatus::Succeeded
            },
            summary: summary.clone(),
            operation_count: envelope.operations.len(),
            touched_paths: touched_paths.clone(),
            touched_regions: touched_regions.clone(),
            operation_kinds,
            preview: summarize_patch_preview(&envelope.operations),
            preview_language: studio_swarm_preview_language(request),
            failure: None,
        },
        StudioArtifactMergeReceipt {
            work_item_id: work_item.id.clone(),
            status: if envelope.operations.is_empty() {
                StudioArtifactWorkItemStatus::Skipped
            } else {
                StudioArtifactWorkItemStatus::Succeeded
            },
            summary,
            applied_operation_count: envelope.operations.len(),
            touched_paths,
            touched_regions,
            rejected_reason: None,
        },
    ))
}

async fn generate_studio_artifact_bundle_with_swarm(
    runtime_plan: StudioArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    execution_strategy: StudioExecutionStrategy,
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
    progress_observer: Option<StudioArtifactGenerationProgressObserver>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    let swarm_started_at = Instant::now();
    let planning_runtime = runtime_plan.planning_runtime.clone();
    let production_runtime = runtime_plan.generation_runtime.clone();
    let acceptance_runtime = runtime_plan.acceptance_runtime.clone();
    let repair_runtime = runtime_plan.repair_runtime.clone();
    let production_provenance = production_runtime.studio_runtime_provenance();
    let acceptance_provenance = acceptance_runtime.studio_runtime_provenance();
    let origin = output_origin_from_provenance(&production_provenance);
    let mut swarm_plan =
        build_studio_artifact_swarm_plan(request, blueprint, brief, execution_strategy);
    let mut worker_receipts = Vec::<StudioArtifactWorkerReceipt>::new();
    let mut patch_receipts = Vec::<StudioArtifactPatchReceipt>::new();
    let mut merge_receipts = Vec::<StudioArtifactMergeReceipt>::new();
    let mut verification_receipts = Vec::<StudioArtifactVerificationReceipt>::new();
    let mut graph_mutation_receipts = Vec::<ExecutionGraphMutationReceipt>::new();
    let mut repair_receipts = Vec::<ExecutionRepairReceipt>::new();
    let mut replan_receipts = Vec::<ExecutionReplanReceipt>::new();
    let mut runtime_dispatch_batches = Vec::<ExecutionDispatchBatch>::new();
    let live_preview_state = Arc::new(Mutex::new(Vec::<ExecutionLivePreview>::new()));
    let mut canonical = StudioGeneratedArtifactPayload {
        summary: if brief.artifact_thesis.trim().is_empty() {
            title.trim().to_string()
        } else {
            brief.artifact_thesis.clone()
        },
        notes: Vec::new(),
        files: Vec::new(),
    };
    let build_error = |message: String| StudioArtifactGenerationError {
        message,
        brief: Some(brief.clone()),
        blueprint: blueprint.cloned(),
        artifact_ir: artifact_ir.cloned(),
        selected_skills: selected_skills.to_vec(),
        edit_intent: edit_intent.cloned(),
        candidate_summaries: Vec::new(),
    };

    update_swarm_work_item_status(
        &mut swarm_plan,
        "planner",
        StudioArtifactWorkItemStatus::Succeeded,
    );
    if let Some(planner_item) = swarm_plan
        .work_items
        .iter()
        .find(|item| item.id == "planner")
    {
        worker_receipts.push(StudioArtifactWorkerReceipt {
            work_item_id: planner_item.id.clone(),
            role: planner_item.role,
            status: StudioArtifactWorkItemStatus::Succeeded,
            result_kind: Some(SwarmWorkerResultKind::Completed),
            summary: format!(
                "Locked {} with {} planned work item(s).",
                swarm_plan.adapter_label,
                swarm_plan.work_items.len()
            ),
            started_at: studio_swarm_now_iso(),
            finished_at: Some(studio_swarm_now_iso()),
            runtime: planning_runtime.studio_runtime_provenance(),
            read_paths: planner_item.read_paths.clone(),
            write_paths: planner_item.write_paths.clone(),
            write_regions: planner_item.write_regions.clone(),
            spawned_work_item_ids: Vec::new(),
            blocked_on_ids: planner_item.blocked_on_ids.clone(),
            prompt_bytes: None,
            output_bytes: None,
            output_preview: None,
            preview_language: None,
            notes: Vec::new(),
            failure: None,
        });
    }

    if request.renderer == StudioRendererKind::HtmlIframe {
        let execution_work_item_ids = swarm_plan
            .work_items
            .iter()
            .filter(|item| {
                matches!(
                    item.role,
                    StudioArtifactWorkerRole::Skeleton
                        | StudioArtifactWorkerRole::SectionContent
                        | StudioArtifactWorkerRole::StyleSystem
                        | StudioArtifactWorkerRole::Interaction
                        | StudioArtifactWorkerRole::Integrator
                )
            })
            .map(|item| item.id.clone())
            .collect::<Vec<_>>();
        let mut dispatch_sequence = 1u32;
        let mut execution_index = 0usize;

        while let Some(mut dispatch_batch) =
            next_swarm_dispatch_batch(&swarm_plan, &execution_work_item_ids, dispatch_sequence)
        {
            dispatch_sequence = dispatch_sequence.saturating_add(1);
            constrain_dispatch_batch_by_parallelism(
                &mut dispatch_batch,
                studio_swarm_dispatch_parallelism_cap(request, production_provenance.kind),
            );
            if dispatch_batch.work_item_ids.is_empty() {
                runtime_dispatch_batches.push(dispatch_batch);
                break;
            }

            let mut runnable_items = Vec::<StudioArtifactWorkItem>::new();
            let mut skipped_ids = Vec::<String>::new();
            for work_item_id in dispatch_batch.work_item_ids.clone() {
                let Some(work_item) = swarm_plan
                    .work_items
                    .iter()
                    .find(|item| item.id == work_item_id)
                    .cloned()
                else {
                    continue;
                };
                if let Some(skip_summary) = studio_swarm_skip_summary_for_html_work_item(
                    request,
                    brief,
                    blueprint,
                    production_provenance.kind,
                    &work_item,
                ) {
                    update_swarm_work_item_status(
                        &mut swarm_plan,
                        &work_item.id,
                        StudioArtifactWorkItemStatus::Skipped,
                    );
                    worker_receipts.push(studio_swarm_skip_receipt(
                        &work_item,
                        &production_runtime,
                        skip_summary,
                    ));
                    skipped_ids.push(work_item.id.clone());
                    continue;
                }
                update_swarm_work_item_status(
                    &mut swarm_plan,
                    &work_item.id,
                    StudioArtifactWorkItemStatus::Running,
                );
                runnable_items.push(work_item);
            }

            if !skipped_ids.is_empty() {
                dispatch_batch
                    .details
                    .push(format!("Skipped {}", skipped_ids.join(" · ")));
            }
            if runnable_items.is_empty() {
                dispatch_batch.status = "skipped".to_string();
                runtime_dispatch_batches.push(dispatch_batch);
                continue;
            }

            let batch_id = dispatch_batch.id.clone();
            let batch_preview_work_item_id = dispatch_batch.work_item_ids.last().cloned();
            let batch_active_role = runnable_items.first().map(|item| item.role);
            let batch_worker_count = runnable_items.len();
            let batch_snapshot = canonical.clone();
            let live_preview_observer: Option<StudioArtifactLivePreviewObserver> =
                progress_observer.as_ref().map(|_| {
                    let progress_observer = progress_observer.clone();
                    let batch_request = request.clone();
                    let batch_swarm_plan = swarm_plan.clone();
                    let batch_worker_receipts = worker_receipts.clone();
                    let batch_patch_receipts = patch_receipts.clone();
                    let batch_merge_receipts = merge_receipts.clone();
                    let batch_verification_receipts = verification_receipts.clone();
                    let batch_graph_mutation_receipts = graph_mutation_receipts.clone();
                    let batch_runtime_dispatch_batches = runtime_dispatch_batches.clone();
                    let batch_repair_receipts = repair_receipts.clone();
                    let batch_replan_receipts = replan_receipts.clone();
                    let live_preview_state = live_preview_state.clone();
                    let batch_id = batch_id.clone();
                    Arc::new(move |preview: ExecutionLivePreview| {
                        if let Ok(mut previews) = live_preview_state.lock() {
                            upsert_execution_live_preview(&mut previews, preview.clone());
                        }
                        let live_previews = snapshot_execution_live_previews(&live_preview_state);
                        emit_studio_swarm_generation_progress(
                            progress_observer.as_ref(),
                            &batch_request,
                            production_provenance.kind,
                            &batch_swarm_plan,
                            &batch_worker_receipts,
                            &batch_patch_receipts,
                            &batch_merge_receipts,
                            &batch_verification_receipts,
                            &batch_graph_mutation_receipts,
                            &batch_runtime_dispatch_batches,
                            &batch_repair_receipts,
                            &batch_replan_receipts,
                            &live_previews,
                            "work",
                            batch_active_role,
                            "running",
                            studio_swarm_progress_step(
                                &studio_swarm_execution_summary(
                                    &batch_swarm_plan,
                                    "work",
                                    batch_active_role,
                                    "running",
                                ),
                                format!("Streaming {} during {}.", preview.label, batch_id),
                            ),
                            None,
                            None,
                        );
                    }) as StudioArtifactLivePreviewObserver
                });
            let mut join_set = JoinSet::new();
            for work_item in &runnable_items {
                let runtime = production_runtime.clone();
                let title = title.to_string();
                let intent = intent.to_string();
                let request = request.clone();
                let brief = brief.clone();
                let blueprint = blueprint.cloned();
                let artifact_ir = artifact_ir.cloned();
                let selected_skills = selected_skills.to_vec();
                let retrieved_exemplars = retrieved_exemplars.to_vec();
                let edit_intent = edit_intent.cloned();
                let refinement = refinement.cloned();
                let current_payload = batch_snapshot.clone();
                let work_item = work_item.clone();
                let worker_context = studio_swarm_work_item_context(
                    &work_item,
                    blueprint.as_ref(),
                    artifact_ir.as_ref(),
                    None,
                );
                let seed = candidate_seed_for(title.as_str(), intent.as_str(), execution_index);
                let worker_live_preview_observer = live_preview_observer.clone();
                execution_index += 1;
                join_set.spawn(async move {
                    execute_studio_swarm_patch_worker(
                        runtime,
                        &title,
                        &intent,
                        &request,
                        &brief,
                        blueprint.as_ref(),
                        artifact_ir.as_ref(),
                        &selected_skills,
                        &retrieved_exemplars,
                        edit_intent.as_ref(),
                        refinement.as_ref(),
                        &current_payload,
                        &work_item,
                        worker_context,
                        seed,
                        worker_live_preview_observer,
                    )
                    .await
                    .map(|(envelope, receipt)| (work_item.id.clone(), envelope, receipt))
                });
            }

            let mut batch_results =
                HashMap::<String, (StudioArtifactPatchEnvelope, StudioArtifactWorkerReceipt)>::new(
                );
            while let Some(join_result) = join_set.join_next().await {
                let execution_result = join_result.map_err(|error| {
                    build_error(format!("Studio swarm worker join failed: {error}"))
                })?;
                let (work_item_id, envelope, receipt) = execution_result.map_err(build_error)?;
                batch_results.insert(work_item_id, (envelope, receipt));
            }

            let mut batch_conflicts = Vec::<String>::new();
            for work_item in runnable_items {
                let Some((envelope, mut receipt)) = batch_results.remove(&work_item.id) else {
                    return Err(build_error(format!(
                        "Studio swarm dispatch batch '{}' lost worker '{}'.",
                        dispatch_batch.id, work_item.id
                    )));
                };
                let (patch_receipt, merge_receipt) = apply_studio_swarm_patch_envelope(
                    request,
                    &mut canonical,
                    &work_item,
                    &envelope,
                )
                .map_err(build_error)?;
                update_swarm_work_item_status(&mut swarm_plan, &work_item.id, patch_receipt.status);
                receipt.result_kind = Some(match patch_receipt.status {
                    StudioArtifactWorkItemStatus::Skipped => SwarmWorkerResultKind::Noop,
                    StudioArtifactWorkItemStatus::Rejected => SwarmWorkerResultKind::Conflict,
                    StudioArtifactWorkItemStatus::Blocked
                    | StudioArtifactWorkItemStatus::Failed => SwarmWorkerResultKind::Blocked,
                    _ => SwarmWorkerResultKind::Completed,
                });
                if let Some(summary) = envelope.summary.as_ref() {
                    canonical.summary = summary.clone();
                }
                canonical.notes.extend(envelope.notes.clone());
                if patch_receipt.status == StudioArtifactWorkItemStatus::Rejected {
                    let rejection_reason = merge_receipt
                        .rejected_reason
                        .clone()
                        .or_else(|| patch_receipt.failure.clone())
                        .unwrap_or_else(|| {
                            format!("{} emitted a bounded patch conflict.", work_item.id)
                        });
                    batch_conflicts.push(format!("{} rejected", work_item.id));
                    graph_mutation_receipts.push(ExecutionGraphMutationReceipt {
                        id: format!("{}-semantic-conflict", work_item.id),
                        mutation_kind: "semantic_conflict_detected".to_string(),
                        status: "blocked".to_string(),
                        summary: rejection_reason.clone(),
                        triggered_by_work_item_id: Some(work_item.id.clone()),
                        affected_work_item_ids: vec![work_item.id.clone()],
                        details: vec![rejection_reason.clone()],
                    });
                    replan_receipts.push(ExecutionReplanReceipt {
                        id: format!("{}-repair-replan", work_item.id),
                        status: "requested".to_string(),
                        summary: format!(
                            "Conflict from '{}' deferred to bounded repair coordination.",
                            work_item.id
                        ),
                        triggered_by_work_item_id: Some(work_item.id.clone()),
                        spawned_work_item_ids: vec!["repair".to_string()],
                        blocked_work_item_ids: vec![work_item.id.clone()],
                        details: vec![rejection_reason],
                    });
                }
                worker_receipts.push(receipt);
                patch_receipts.push(patch_receipt);
                merge_receipts.push(merge_receipt);
            }

            dispatch_batch.status = if !batch_conflicts.is_empty() {
                dispatch_batch.details.extend(batch_conflicts);
                "conflicted".to_string()
            } else if !dispatch_batch.deferred_work_item_ids.is_empty()
                || !dispatch_batch.blocked_work_item_ids.is_empty()
            {
                "constrained".to_string()
            } else {
                "executed".to_string()
            };
            runtime_dispatch_batches.push(dispatch_batch);
            if let Some(preview) = studio_swarm_canonical_preview(
                &canonical,
                batch_preview_work_item_id,
                batch_active_role,
                "running",
                false,
            ) {
                if let Ok(mut previews) = live_preview_state.lock() {
                    upsert_execution_live_preview(&mut previews, preview);
                }
            }
            emit_studio_swarm_generation_progress(
                progress_observer.as_ref(),
                request,
                production_provenance.kind,
                &swarm_plan,
                &worker_receipts,
                &patch_receipts,
                &merge_receipts,
                &verification_receipts,
                &graph_mutation_receipts,
                &runtime_dispatch_batches,
                &repair_receipts,
                &replan_receipts,
                &snapshot_execution_live_previews(&live_preview_state),
                "work",
                batch_active_role,
                "running",
                studio_swarm_progress_step(
                    &studio_swarm_execution_summary(
                        &swarm_plan,
                        "work",
                        batch_active_role,
                        "running",
                    ),
                    format!(
                        "Merged dispatch batch {} with {} worker result(s).",
                        batch_id, batch_worker_count
                    ),
                ),
                None,
                None,
            );
        }
    } else {
        let skeleton_item = swarm_plan
            .work_items
            .iter()
            .find(|item| item.id == "skeleton")
            .cloned()
            .ok_or_else(|| build_error("Swarm skeleton work item is missing.".to_string()))?;
        let generated = materialize_studio_artifact_candidate_with_runtime_detailed(
            production_runtime.clone(),
            Some(repair_runtime.clone()),
            title,
            intent,
            request,
            brief,
            blueprint,
            artifact_ir,
            selected_skills,
            retrieved_exemplars,
            edit_intent,
            refinement,
            "swarm-skeleton",
            candidate_seed_for(title, intent, 0),
            studio_swarm_worker_temperature(
                request,
                StudioArtifactWorkerRole::Skeleton,
                production_provenance.kind,
            ),
        )
        .await
        .map_err(|error| build_error(error.message))?;
        let envelope = StudioArtifactPatchEnvelope {
            summary: Some(generated.summary.clone()),
            notes: generated.notes.clone(),
            operations: diff_payloads_to_patch_operations(&canonical, &generated),
        };
        let (patch_receipt, merge_receipt) =
            apply_studio_swarm_patch_envelope(request, &mut canonical, &skeleton_item, &envelope)
                .map_err(build_error)?;
        update_swarm_work_item_status(&mut swarm_plan, &skeleton_item.id, patch_receipt.status);
        canonical.summary = generated.summary.clone();
        canonical.notes.extend(generated.notes.clone());
        worker_receipts.push(StudioArtifactWorkerReceipt {
            work_item_id: skeleton_item.id.clone(),
            role: skeleton_item.role,
            status: StudioArtifactWorkItemStatus::Succeeded,
            result_kind: Some(SwarmWorkerResultKind::Completed),
            summary: generated.summary,
            started_at: studio_swarm_now_iso(),
            finished_at: Some(studio_swarm_now_iso()),
            runtime: production_runtime.studio_runtime_provenance(),
            read_paths: skeleton_item.read_paths.clone(),
            write_paths: skeleton_item.write_paths.clone(),
            write_regions: skeleton_item.write_regions.clone(),
            spawned_work_item_ids: Vec::new(),
            blocked_on_ids: skeleton_item.blocked_on_ids.clone(),
            prompt_bytes: None,
            output_bytes: None,
            output_preview: None,
            preview_language: studio_swarm_preview_language(request),
            notes: generated.notes,
            failure: None,
        });
        patch_receipts.push(patch_receipt);
        merge_receipts.push(merge_receipt);

        if let Some(integrator_item) = swarm_plan
            .work_items
            .iter()
            .find(|item| item.id == "integrator")
            .cloned()
        {
            update_swarm_work_item_status(
                &mut swarm_plan,
                &integrator_item.id,
                StudioArtifactWorkItemStatus::Skipped,
            );
            worker_receipts.push(studio_swarm_skip_receipt(
                &integrator_item,
                &production_runtime,
                "The coarse renderer adapter completed within the initial bounded pass.",
            ));
        }
        runtime_dispatch_batches = plan_swarm_dispatch_batches(&swarm_plan);
    }

    let mut final_payload =
        validate_swarm_generated_artifact_payload(&canonical, request).map_err(build_error)?;
    verification_receipts.push(StudioArtifactVerificationReceipt {
        id: "schema-validation".to_string(),
        kind: "schema_validation".to_string(),
        status: "success".to_string(),
        summary: "Canonical artifact payload validated against the renderer contract.".to_string(),
        details: final_payload
            .files
            .iter()
            .map(|file| file.path.clone())
            .collect(),
    });

    let mut render_evaluation = evaluate_candidate_render_with_fallback(
        render_evaluator,
        request,
        brief,
        blueprint,
        artifact_ir,
        edit_intent,
        &final_payload,
        production_provenance.kind,
    )
    .await;
    verification_receipts.push(StudioArtifactVerificationReceipt {
        id: "render-evaluation".to_string(),
        kind: "render_evaluation".to_string(),
        status: if render_evaluation.is_some() {
            "success"
        } else {
            "skipped"
        }
        .to_string(),
        summary: render_evaluation
            .as_ref()
            .map(|value| value.summary.clone())
            .unwrap_or_else(|| "Render evaluation was not required for this renderer.".to_string()),
        details: render_evaluation
            .as_ref()
            .map(|value| {
                value
                    .findings
                    .iter()
                    .map(|finding| format!("{}: {}", finding.code, finding.summary))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default(),
    });
    emit_studio_swarm_generation_progress(
        progress_observer.as_ref(),
        request,
        production_provenance.kind,
        &swarm_plan,
        &worker_receipts,
        &patch_receipts,
        &merge_receipts,
        &verification_receipts,
        &graph_mutation_receipts,
        &runtime_dispatch_batches,
        &repair_receipts,
        &replan_receipts,
        &snapshot_execution_live_previews(&live_preview_state),
        "verify",
        Some(StudioArtifactWorkerRole::Judge),
        "running",
        studio_swarm_progress_step(
            &studio_swarm_execution_summary(
                &swarm_plan,
                "verify",
                Some(StudioArtifactWorkerRole::Judge),
                "running",
            ),
            "Render evaluation finished and acceptance judging is starting.",
        ),
        render_evaluation.as_ref(),
        None,
    );

    let judge_item = swarm_plan
        .work_items
        .iter()
        .find(|item| item.id == "judge")
        .cloned()
        .ok_or_else(|| build_error("Swarm judge work item is missing.".to_string()))?;
    let mut judge = judge_candidate_with_runtime_and_render_eval(
        acceptance_runtime.clone(),
        render_evaluation.as_ref(),
        title,
        request,
        brief,
        edit_intent,
        &final_payload,
    )
    .await
    .map_err(build_error)?;
    update_swarm_work_item_status(
        &mut swarm_plan,
        &judge_item.id,
        StudioArtifactWorkItemStatus::Succeeded,
    );
    worker_receipts.push(StudioArtifactWorkerReceipt {
        work_item_id: judge_item.id,
        role: judge_item.role,
        status: StudioArtifactWorkItemStatus::Succeeded,
        result_kind: Some(SwarmWorkerResultKind::Completed),
        summary: judge.rationale.clone(),
        started_at: studio_swarm_now_iso(),
        finished_at: Some(studio_swarm_now_iso()),
        runtime: acceptance_runtime.studio_runtime_provenance(),
        read_paths: Vec::new(),
        write_paths: Vec::new(),
        write_regions: Vec::new(),
        spawned_work_item_ids: Vec::new(),
        blocked_on_ids: Vec::new(),
        prompt_bytes: None,
        output_bytes: None,
        output_preview: None,
        preview_language: None,
        notes: judge.strengths.clone(),
        failure: None,
    });
    verification_receipts.push(StudioArtifactVerificationReceipt {
        id: "acceptance-judge".to_string(),
        kind: "acceptance_judge".to_string(),
        status: judge_classification_id(judge.classification).to_string(),
        summary: judge.rationale.clone(),
        details: judge.issue_classes.clone(),
    });
    emit_studio_swarm_generation_progress(
        progress_observer.as_ref(),
        request,
        production_provenance.kind,
        &swarm_plan,
        &worker_receipts,
        &patch_receipts,
        &merge_receipts,
        &verification_receipts,
        &graph_mutation_receipts,
        &runtime_dispatch_batches,
        &repair_receipts,
        &replan_receipts,
        &snapshot_execution_live_previews(&live_preview_state),
        "verify",
        Some(StudioArtifactWorkerRole::Judge),
        judge_classification_id(judge.classification),
        studio_swarm_progress_step(
            &studio_swarm_execution_summary(
                &swarm_plan,
                "verify",
                Some(StudioArtifactWorkerRole::Judge),
                judge_classification_id(judge.classification),
            ),
            format!(
                "Acceptance judge returned {}.",
                judge_classification_id(judge.classification)
            ),
        ),
        render_evaluation.as_ref(),
        Some(&judge),
    );

    let mut repair_applied = false;
    if !judge_clears_primary_view(&judge) {
        let repair_template_item = swarm_plan
            .work_items
            .iter()
            .find(|item| item.id == "repair")
            .cloned()
            .ok_or_else(|| build_error("Swarm repair work item is missing.".to_string()))?;
        graph_mutation_receipts.push(ExecutionGraphMutationReceipt {
            id: "repair-requested".to_string(),
            mutation_kind: "repair_requested".to_string(),
            status: "applied".to_string(),
            summary: "Acceptance verification requested a scoped repair pass.".to_string(),
            triggered_by_work_item_id: Some("acceptance-judge".to_string()),
            affected_work_item_ids: vec![repair_template_item.id.clone()],
            details: judge.repair_hints.clone(),
        });
        replan_receipts.push(ExecutionReplanReceipt {
            id: "repair-replan".to_string(),
            status: "requested".to_string(),
            summary: "Acceptance judge blocked the merged artifact and requested bounded repair coordination.".to_string(),
            triggered_by_work_item_id: Some("acceptance-judge".to_string()),
            spawned_work_item_ids: vec![repair_template_item.id.clone()],
            blocked_work_item_ids: vec!["acceptance-judge".to_string()],
            details: judge.repair_hints.clone(),
        });
        let repair_budget = if request.renderer == StudioRendererKind::HtmlIframe
            && production_provenance.kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        {
            2
        } else {
            semantic_refinement_pass_limit(request.renderer, production_provenance.kind).clamp(1, 2)
        };
        let mut spawned_repair_work_item_ids = Vec::<String>::new();
        for repair_index in 0..repair_budget {
            let prior_repair_pass_id = spawned_repair_work_item_ids.last().cloned();
            let mut repair_patch_applied = false;
            let repair_template_ids =
                if request.renderer == StudioRendererKind::HtmlIframe && repair_index == 0 {
                    html_swarm_targeted_repair_template_ids(&judge)
                } else {
                    vec!["repair"]
                };
            let repair_template_count = repair_template_ids.len();
            let mut repair_wave_work_item_ids = Vec::<String>::new();
            let mut repair_wave_dependency_id = prior_repair_pass_id.clone();

            for template_id in repair_template_ids {
                let repair_source_template = swarm_plan
                    .work_items
                    .iter()
                    .find(|item| item.id == template_id)
                    .cloned()
                    .ok_or_else(|| {
                        build_error(format!(
                            "Swarm repair follow-up work item template '{}' is missing.",
                            template_id
                        ))
                    })?;
                let repair_pass_id = if repair_template_count == 1 && template_id == "repair" {
                    format!("repair-pass-{}", repair_index + 1)
                } else {
                    format!("repair-pass-{}-{}", repair_index + 1, template_id)
                };
                let mut repair_dependency_ids = repair_source_template.dependency_ids.clone();
                if let Some(previous_id) = repair_wave_dependency_id.as_ref() {
                    repair_dependency_ids.push(previous_id.clone());
                }
                let repair_item = StudioArtifactWorkItem {
                    id: repair_pass_id.clone(),
                    title: if repair_template_count == 1 && template_id == "repair" {
                        format!("Repair pass {}", repair_index + 1)
                    } else {
                        format!(
                            "Repair pass {} · {}",
                            repair_index + 1,
                            repair_source_template.title
                        )
                    },
                    role: repair_source_template.role,
                    summary: judge
                        .strongest_contradiction
                        .as_ref()
                        .map(|value| format!("Resolve the current verification block: {value}"))
                        .unwrap_or_else(|| repair_source_template.summary.clone()),
                    spawned_from_id: Some(repair_template_item.id.clone()),
                    read_paths: repair_source_template.read_paths.clone(),
                    write_paths: repair_source_template.write_paths.clone(),
                    write_regions: repair_source_template.write_regions.clone(),
                    lease_requirements: repair_source_template.lease_requirements.clone(),
                    acceptance_criteria: repair_source_template.acceptance_criteria.clone(),
                    dependency_ids: repair_dependency_ids,
                    blocked_on_ids: repair_wave_dependency_id.clone().into_iter().collect(),
                    verification_policy: repair_source_template.verification_policy,
                    retry_budget: Some(0),
                    status: StudioArtifactWorkItemStatus::Pending,
                };
                spawn_follow_up_swarm_work_item(&mut swarm_plan, repair_item.clone())
                    .map_err(build_error)?;
                spawned_repair_work_item_ids.push(repair_pass_id.clone());
                repair_wave_work_item_ids.push(repair_pass_id.clone());
                update_swarm_work_item_status(
                    &mut swarm_plan,
                    &repair_item.id,
                    StudioArtifactWorkItemStatus::Running,
                );
                graph_mutation_receipts.push(ExecutionGraphMutationReceipt {
                    id: format!("{}-spawned", repair_pass_id),
                    mutation_kind: if repair_index == 0 {
                        "subtask_spawned".to_string()
                    } else {
                        "follow_up_spawned".to_string()
                    },
                    status: "applied".to_string(),
                    summary: if let Some(previous_id) = repair_wave_dependency_id.as_ref() {
                        format!(
                            "Repair coordination queued {} after {} did not clear verification.",
                            repair_pass_id, previous_id
                        )
                    } else {
                        format!(
                            "Repair coordination queued {} as the first bounded follow-up worker.",
                            repair_pass_id
                        )
                    },
                    triggered_by_work_item_id: Some(
                        repair_wave_dependency_id
                            .clone()
                            .unwrap_or_else(|| "acceptance-judge".to_string()),
                    ),
                    affected_work_item_ids: vec![
                        repair_template_item.id.clone(),
                        repair_source_template.id.clone(),
                        repair_pass_id.clone(),
                    ],
                    details: judge.repair_hints.clone(),
                });
                repair_receipts.push(ExecutionRepairReceipt {
                    id: repair_pass_id.clone(),
                    status: "running".to_string(),
                    summary: format!(
                        "{} is applying a bounded fix against the merged artifact.",
                        repair_item.title
                    ),
                    triggered_by_verification_id: Some("acceptance-judge".to_string()),
                    work_item_ids: vec![
                        repair_template_item.id.clone(),
                        repair_source_template.id.clone(),
                        repair_item.id.clone(),
                    ],
                    details: judge.repair_hints.clone(),
                });
                emit_studio_swarm_generation_progress(
                    progress_observer.as_ref(),
                    request,
                    production_provenance.kind,
                    &swarm_plan,
                    &worker_receipts,
                    &patch_receipts,
                    &merge_receipts,
                    &verification_receipts,
                    &graph_mutation_receipts,
                    &runtime_dispatch_batches,
                    &repair_receipts,
                    &replan_receipts,
                    &snapshot_execution_live_previews(&live_preview_state),
                    "mutate",
                    Some(repair_item.role),
                    "repairing",
                    studio_swarm_progress_step(
                        &studio_swarm_execution_summary(
                            &swarm_plan,
                            "mutate",
                            Some(repair_item.role),
                            "repairing",
                        ),
                        format!("Running {} after acceptance blocking.", repair_item.title),
                    ),
                    render_evaluation.as_ref(),
                    Some(&judge),
                );

                if request.renderer == StudioRendererKind::HtmlIframe {
                    let repair_live_preview_observer: Option<StudioArtifactLivePreviewObserver> =
                        progress_observer.as_ref().map(|_| {
                            let progress_observer = progress_observer.clone();
                            let repair_request = request.clone();
                            let repair_swarm_plan = swarm_plan.clone();
                            let repair_worker_receipts = worker_receipts.clone();
                            let repair_patch_receipts = patch_receipts.clone();
                            let repair_merge_receipts = merge_receipts.clone();
                            let repair_verification_receipts = verification_receipts.clone();
                            let repair_graph_mutation_receipts = graph_mutation_receipts.clone();
                            let repair_runtime_dispatch_batches = runtime_dispatch_batches.clone();
                            let repair_receipts_snapshot = repair_receipts.clone();
                            let repair_replan_receipts = replan_receipts.clone();
                            let live_preview_state = live_preview_state.clone();
                            let repair_title = repair_item.title.clone();
                            Arc::new(move |preview: ExecutionLivePreview| {
                                if let Ok(mut previews) = live_preview_state.lock() {
                                    upsert_execution_live_preview(&mut previews, preview.clone());
                                }
                                let live_previews =
                                    snapshot_execution_live_previews(&live_preview_state);
                                emit_studio_swarm_generation_progress(
                                    progress_observer.as_ref(),
                                    &repair_request,
                                    production_provenance.kind,
                                    &repair_swarm_plan,
                                    &repair_worker_receipts,
                                    &repair_patch_receipts,
                                    &repair_merge_receipts,
                                    &repair_verification_receipts,
                                    &repair_graph_mutation_receipts,
                                    &repair_runtime_dispatch_batches,
                                    &repair_receipts_snapshot,
                                    &repair_replan_receipts,
                                    &live_previews,
                                    "mutate",
                                    Some(StudioArtifactWorkerRole::Repair),
                                    "repairing",
                                    studio_swarm_progress_step(
                                        &studio_swarm_execution_summary(
                                            &repair_swarm_plan,
                                            "mutate",
                                            Some(StudioArtifactWorkerRole::Repair),
                                            "repairing",
                                        ),
                                        format!(
                                            "Streaming {} while {} is running.",
                                            preview.label, repair_title
                                        ),
                                    ),
                                    None,
                                    None,
                                );
                            }) as StudioArtifactLivePreviewObserver
                        });
                    let (envelope, mut receipt) = execute_studio_swarm_patch_worker(
                        repair_runtime.clone(),
                        title,
                        intent,
                        request,
                        brief,
                        blueprint,
                        artifact_ir,
                        selected_skills,
                        retrieved_exemplars,
                        edit_intent,
                        refinement,
                        &canonical,
                        &repair_item,
                        studio_swarm_work_item_context(
                            &repair_item,
                            blueprint,
                            artifact_ir,
                            Some(&judge),
                        ),
                        candidate_seed_for(title, intent, 900 + repair_index),
                        repair_live_preview_observer,
                    )
                    .await
                    .map_err(build_error)?;
                    let (patch_receipt, merge_receipt) = apply_studio_swarm_patch_envelope(
                        request,
                        &mut canonical,
                        &repair_item,
                        &envelope,
                    )
                    .map_err(build_error)?;
                    repair_patch_applied =
                        repair_patch_applied || patch_receipt.operation_count > 0;
                    repair_applied = repair_applied || patch_receipt.operation_count > 0;
                    update_swarm_work_item_status(
                        &mut swarm_plan,
                        &repair_item.id,
                        patch_receipt.status,
                    );
                    receipt.result_kind = Some(match patch_receipt.status {
                        StudioArtifactWorkItemStatus::Skipped => SwarmWorkerResultKind::Noop,
                        StudioArtifactWorkItemStatus::Rejected => SwarmWorkerResultKind::Conflict,
                        StudioArtifactWorkItemStatus::Blocked
                        | StudioArtifactWorkItemStatus::Failed => SwarmWorkerResultKind::Blocked,
                        _ => SwarmWorkerResultKind::Completed,
                    });
                    if let Some(summary) = envelope.summary.as_ref() {
                        canonical.summary = summary.clone();
                    }
                    canonical.notes.extend(envelope.notes.clone());
                    worker_receipts.push(receipt);
                    patch_receipts.push(patch_receipt);
                    merge_receipts.push(merge_receipt);
                } else if renderer_supports_semantic_refinement(request.renderer) {
                    let refined = refine_studio_artifact_candidate_with_runtime(
                        repair_runtime.clone(),
                        title,
                        intent,
                        request,
                        brief,
                        blueprint,
                        artifact_ir,
                        selected_skills,
                        retrieved_exemplars,
                        edit_intent,
                        refinement,
                        &final_payload,
                        &judge,
                        "swarm-repair",
                        candidate_seed_for(title, intent, 900 + repair_index),
                        0.18,
                    )
                    .await
                    .map_err(build_error)?;
                    let envelope = StudioArtifactPatchEnvelope {
                        summary: Some(refined.summary.clone()),
                        notes: refined.notes.clone(),
                        operations: diff_payloads_to_patch_operations(&canonical, &refined),
                    };
                    let (patch_receipt, merge_receipt) = apply_studio_swarm_patch_envelope(
                        request,
                        &mut canonical,
                        &repair_item,
                        &envelope,
                    )
                    .map_err(build_error)?;
                    repair_patch_applied =
                        repair_patch_applied || patch_receipt.operation_count > 0;
                    repair_applied = repair_applied || patch_receipt.operation_count > 0;
                    update_swarm_work_item_status(
                        &mut swarm_plan,
                        &repair_item.id,
                        patch_receipt.status,
                    );
                    canonical.summary = refined.summary.clone();
                    canonical.notes.extend(refined.notes.clone());
                    worker_receipts.push(StudioArtifactWorkerReceipt {
                        work_item_id: repair_item.id.clone(),
                        role: repair_item.role,
                        status: StudioArtifactWorkItemStatus::Succeeded,
                        result_kind: Some(SwarmWorkerResultKind::Completed),
                        summary: refined.summary,
                        started_at: studio_swarm_now_iso(),
                        finished_at: Some(studio_swarm_now_iso()),
                        runtime: repair_runtime.studio_runtime_provenance(),
                        read_paths: repair_item.read_paths.clone(),
                        write_paths: repair_item.write_paths.clone(),
                        write_regions: repair_item.write_regions.clone(),
                        spawned_work_item_ids: Vec::new(),
                        blocked_on_ids: repair_item.blocked_on_ids.clone(),
                        prompt_bytes: None,
                        output_bytes: None,
                        output_preview: None,
                        preview_language: studio_swarm_preview_language(request),
                        notes: refined.notes,
                        failure: None,
                    });
                    patch_receipts.push(patch_receipt);
                    merge_receipts.push(merge_receipt);
                }

                if let Some(preview) = studio_swarm_canonical_preview(
                    &canonical,
                    Some(repair_item.id.clone()),
                    Some(repair_item.role),
                    "repairing",
                    false,
                ) {
                    if let Ok(mut previews) = live_preview_state.lock() {
                        upsert_execution_live_preview(&mut previews, preview);
                    }
                }

                repair_wave_dependency_id = Some(repair_pass_id);
            }

            final_payload = validate_swarm_generated_artifact_payload(&canonical, request)
                .map_err(build_error)?;
            render_evaluation = evaluate_candidate_render_with_fallback(
                render_evaluator,
                request,
                brief,
                blueprint,
                artifact_ir,
                edit_intent,
                &final_payload,
                production_provenance.kind,
            )
            .await;
            judge = judge_candidate_with_runtime_and_render_eval(
                acceptance_runtime.clone(),
                render_evaluation.as_ref(),
                title,
                request,
                brief,
                edit_intent,
                &final_payload,
            )
            .await
            .map_err(build_error)?;
            verification_receipts.push(StudioArtifactVerificationReceipt {
                id: format!("repair-pass-{}", repair_index + 1),
                kind: "repair_verification".to_string(),
                status: judge_classification_id(judge.classification).to_string(),
                summary: judge.rationale.clone(),
                details: judge.repair_hints.clone(),
            });
            for repair_receipt in repair_receipts.iter_mut().filter(|receipt| {
                repair_wave_work_item_ids
                    .iter()
                    .any(|work_item_id| work_item_id == &receipt.id)
            }) {
                repair_receipt.status = judge_classification_id(judge.classification).to_string();
                repair_receipt.summary = if repair_patch_applied {
                    "Scoped repair changes were merged and re-verified.".to_string()
                } else {
                    "Repair pass completed without any scoped change to merge.".to_string()
                };
                repair_receipt.details = judge.repair_hints.clone();
            }
            emit_studio_swarm_generation_progress(
                progress_observer.as_ref(),
                request,
                production_provenance.kind,
                &swarm_plan,
                &worker_receipts,
                &patch_receipts,
                &merge_receipts,
                &verification_receipts,
                &graph_mutation_receipts,
                &runtime_dispatch_batches,
                &repair_receipts,
                &replan_receipts,
                &snapshot_execution_live_previews(&live_preview_state),
                "verify",
                Some(StudioArtifactWorkerRole::Repair),
                judge_classification_id(judge.classification),
                studio_swarm_progress_step(
                    &studio_swarm_execution_summary(
                        &swarm_plan,
                        "verify",
                        Some(StudioArtifactWorkerRole::Repair),
                        judge_classification_id(judge.classification),
                    ),
                    format!("Repair pass {} re-ran verification.", repair_index + 1),
                ),
                render_evaluation.as_ref(),
                Some(&judge),
            );
            if judge_clears_primary_view(&judge) {
                break;
            }
        }
        if !spawned_repair_work_item_ids.is_empty() {
            replan_receipts.push(ExecutionReplanReceipt {
                id: "repair-follow-up-graph".to_string(),
                status: if judge_clears_primary_view(&judge) {
                    "applied".to_string()
                } else {
                    "partial".to_string()
                },
                summary: format!(
                    "Repair coordination expanded the work graph with {} bounded follow-up worker(s).",
                    spawned_repair_work_item_ids.len()
                ),
                triggered_by_work_item_id: Some(repair_template_item.id.clone()),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_work_item_ids: Vec::new(),
                details: judge.repair_hints.clone(),
            });
        }
        if repair_applied && judge_clears_primary_view(&judge) {
            update_swarm_work_item_status(
                &mut swarm_plan,
                &repair_template_item.id,
                StudioArtifactWorkItemStatus::Succeeded,
            );
            worker_receipts.push(StudioArtifactWorkerReceipt {
                work_item_id: repair_template_item.id.clone(),
                role: repair_template_item.role,
                status: StudioArtifactWorkItemStatus::Succeeded,
                result_kind: Some(SwarmWorkerResultKind::SubtaskRequested),
                summary: format!(
                    "Repair coordination spawned {} bounded follow-up worker(s) and cleared verification.",
                    spawned_repair_work_item_ids.len()
                ),
                started_at: studio_swarm_now_iso(),
                finished_at: Some(studio_swarm_now_iso()),
                runtime: repair_runtime.studio_runtime_provenance(),
                read_paths: repair_template_item.read_paths.clone(),
                write_paths: repair_template_item.write_paths.clone(),
                write_regions: repair_template_item.write_regions.clone(),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_on_ids: Vec::new(),
                prompt_bytes: None,
                output_bytes: None,
                output_preview: None,
                preview_language: None,
                notes: judge.repair_hints.clone(),
                failure: None,
            });
        } else if !repair_applied {
            update_swarm_work_item_status(
                &mut swarm_plan,
                &repair_template_item.id,
                StudioArtifactWorkItemStatus::Blocked,
            );
            worker_receipts.push(StudioArtifactWorkerReceipt {
                work_item_id: repair_template_item.id.clone(),
                role: repair_template_item.role,
                status: StudioArtifactWorkItemStatus::Blocked,
                result_kind: Some(SwarmWorkerResultKind::Blocked),
                summary: "Judge cited issues, but no narrower repair patch was applied."
                    .to_string(),
                started_at: studio_swarm_now_iso(),
                finished_at: Some(studio_swarm_now_iso()),
                runtime: repair_runtime.studio_runtime_provenance(),
                read_paths: repair_template_item.read_paths.clone(),
                write_paths: repair_template_item.write_paths.clone(),
                write_regions: repair_template_item.write_regions.clone(),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_on_ids: Vec::new(),
                prompt_bytes: None,
                output_bytes: None,
                output_preview: None,
                preview_language: None,
                notes: judge.repair_hints.clone(),
                failure: Some(
                    "Repair coordination completed without any scoped patch to merge.".to_string(),
                ),
            });
            graph_mutation_receipts.push(ExecutionGraphMutationReceipt {
                id: "repair-skipped".to_string(),
                mutation_kind: "repair_exhausted".to_string(),
                status: "blocked".to_string(),
                summary: "Repair coordination completed without any scoped patch to merge."
                    .to_string(),
                triggered_by_work_item_id: Some(repair_template_item.id.clone()),
                affected_work_item_ids: vec![repair_template_item.id.clone()],
                details: judge.repair_hints.clone(),
            });
            replan_receipts.push(ExecutionReplanReceipt {
                id: "repair-follow-up-blocked".to_string(),
                status: "blocked".to_string(),
                summary: "Repair coordination could not merge any bounded follow-up change."
                    .to_string(),
                triggered_by_work_item_id: Some(repair_template_item.id.clone()),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_work_item_ids: vec![repair_template_item.id.clone()],
                details: judge.repair_hints.clone(),
            });
        } else {
            update_swarm_work_item_status(
                &mut swarm_plan,
                &repair_template_item.id,
                StudioArtifactWorkItemStatus::Blocked,
            );
            worker_receipts.push(StudioArtifactWorkerReceipt {
                work_item_id: repair_template_item.id.clone(),
                role: repair_template_item.role,
                status: StudioArtifactWorkItemStatus::Blocked,
                result_kind: Some(SwarmWorkerResultKind::ReplanRequested),
                summary: format!(
                    "Repair coordination merged {} bounded follow-up worker(s), but verification still needs a broader replan.",
                    spawned_repair_work_item_ids.len()
                ),
                started_at: studio_swarm_now_iso(),
                finished_at: Some(studio_swarm_now_iso()),
                runtime: repair_runtime.studio_runtime_provenance(),
                read_paths: repair_template_item.read_paths.clone(),
                write_paths: repair_template_item.write_paths.clone(),
                write_regions: repair_template_item.write_regions.clone(),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_on_ids: Vec::new(),
                prompt_bytes: None,
                output_bytes: None,
                output_preview: None,
                preview_language: None,
                notes: judge.repair_hints.clone(),
                failure: Some(judge.rationale.clone()),
            });
            graph_mutation_receipts.push(ExecutionGraphMutationReceipt {
                id: "repair-replan-requested".to_string(),
                mutation_kind: "replan_requested".to_string(),
                status: "blocked".to_string(),
                summary:
                    "Scoped repair passes improved the artifact but did not clear verification."
                        .to_string(),
                triggered_by_work_item_id: Some(repair_template_item.id.clone()),
                affected_work_item_ids: vec![repair_template_item.id.clone()],
                details: judge.repair_hints.clone(),
            });
            replan_receipts.push(ExecutionReplanReceipt {
                id: "repair-broader-replan".to_string(),
                status: "blocked".to_string(),
                summary:
                    "Bounded repair passes improved the artifact, but broader replanning is still required."
                        .to_string(),
                triggered_by_work_item_id: Some(repair_template_item.id.clone()),
                spawned_work_item_ids: spawned_repair_work_item_ids.clone(),
                blocked_work_item_ids: vec![repair_template_item.id.clone()],
                details: judge.repair_hints.clone(),
            });
        }
    } else {
        update_swarm_work_item_status(
            &mut swarm_plan,
            "repair",
            StudioArtifactWorkItemStatus::Skipped,
        );
        if let Some(repair_item) = swarm_plan
            .work_items
            .iter()
            .find(|item| item.id == "repair")
        {
            worker_receipts.push(studio_swarm_skip_receipt(
                repair_item,
                &repair_runtime,
                "Judge cleared the merged artifact without a repair pass.",
            ));
        }
    }

    final_payload =
        validate_swarm_generated_artifact_payload(&canonical, request).map_err(build_error)?;
    let swarm_execution = studio_swarm_execution_summary(
        &swarm_plan,
        if judge_clears_primary_view(&judge) {
            "ready"
        } else if repair_applied {
            "repair_exhausted"
        } else {
            "judged"
        },
        None,
        judge_classification_id(judge.classification),
    );
    let execution_budget_summary = ExecutionBudgetSummary {
        planned_worker_count: Some(swarm_plan.work_items.len()),
        dispatched_worker_count: Some(
            worker_receipts
                .iter()
                .filter(|receipt| {
                    !matches!(
                        receipt.result_kind,
                        Some(SwarmWorkerResultKind::Noop) | Some(SwarmWorkerResultKind::Blocked)
                    )
                })
                .count(),
        ),
        token_budget: Some(studio_swarm_planned_token_budget(
            request,
            production_provenance.kind,
            &swarm_plan,
        )),
        token_usage: None,
        wall_clock_ms: Some(swarm_started_at.elapsed().as_millis() as u64),
        coordination_overhead_ms: None,
        status: if judge_clears_primary_view(&judge) {
            "completed".to_string()
        } else if repair_applied {
            "repair_exhausted".to_string()
        } else {
            "judged".to_string()
        },
    };
    let execution_envelope = build_execution_envelope_from_swarm_with_receipts(
        Some(execution_strategy),
        Some("studio_artifact".to_string()),
        Some(ExecutionDomainKind::Artifact),
        Some(&swarm_plan),
        Some(&swarm_execution),
        &worker_receipts,
        &patch_receipts,
        &merge_receipts,
        &verification_receipts,
        &graph_mutation_receipts,
        &runtime_dispatch_batches,
        &repair_receipts,
        &replan_receipts,
        Some(execution_budget_summary),
        &snapshot_execution_live_previews(&live_preview_state),
    );

    Ok(StudioArtifactGenerationBundle {
        brief: brief.clone(),
        blueprint: blueprint.cloned(),
        artifact_ir: artifact_ir.cloned(),
        selected_skills: selected_skills.to_vec(),
        edit_intent: edit_intent.cloned(),
        candidate_summaries: Vec::new(),
        winning_candidate_id: None,
        winning_candidate_rationale: None,
        execution_envelope,
        swarm_plan: Some(swarm_plan),
        swarm_execution: Some(swarm_execution),
        swarm_worker_receipts: worker_receipts,
        swarm_change_receipts: patch_receipts,
        swarm_merge_receipts: merge_receipts,
        swarm_verification_receipts: verification_receipts,
        winner: final_payload,
        render_evaluation,
        judge,
        origin,
        production_provenance,
        acceptance_provenance,
        runtime_policy: Some(runtime_plan.policy),
        adaptive_search_budget: None,
        fallback_used: false,
        ux_lifecycle: if repair_applied {
            StudioArtifactUxLifecycle::Refining
        } else {
            StudioArtifactUxLifecycle::Judged
        },
        taste_memory: refinement.and_then(|context| context.taste_memory.clone()),
        failure: None,
    })
}

pub async fn generate_studio_artifact_bundle_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    let runtime_plan = resolve_studio_artifact_runtime_plan(
        request,
        runtime,
        None,
        StudioArtifactRuntimePolicyProfile::FullyLocal,
    );
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        None,
        default_studio_artifact_execution_strategy(request),
        None,
    )
    .await
}

pub async fn generate_studio_artifact_bundle_with_runtimes(
    production_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    let runtime_plan = resolve_studio_artifact_runtime_plan(
        request,
        production_runtime,
        Some(acceptance_runtime),
        StudioArtifactRuntimePolicyProfile::Auto,
    );
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        None,
        default_studio_artifact_execution_strategy(request),
        None,
    )
    .await
}

pub async fn generate_studio_artifact_bundle_with_runtimes_and_planning_context(
    production_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Option<Arc<dyn InferenceRuntime>>,
    runtime_profile: StudioArtifactRuntimePolicyProfile,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: Option<&StudioArtifactPlanningContext>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    generate_studio_artifact_bundle_with_runtimes_and_planning_context_and_render_evaluator(
        production_runtime,
        acceptance_runtime,
        runtime_profile,
        title,
        intent,
        request,
        refinement,
        planning_context,
        None,
    )
    .await
}

pub async fn generate_studio_artifact_bundle_with_runtimes_and_planning_context_and_render_evaluator(
    production_runtime: Arc<dyn InferenceRuntime>,
    acceptance_runtime: Option<Arc<dyn InferenceRuntime>>,
    runtime_profile: StudioArtifactRuntimePolicyProfile,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: Option<&StudioArtifactPlanningContext>,
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    let runtime_plan = resolve_studio_artifact_runtime_plan(
        request,
        production_runtime,
        acceptance_runtime,
        runtime_profile,
    );
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        planning_context,
        default_studio_artifact_execution_strategy(request),
        render_evaluator,
        None,
    )
    .await
}

pub async fn generate_studio_artifact_bundle_with_runtime_plan_and_planning_context(
    runtime_plan: StudioArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: Option<&StudioArtifactPlanningContext>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        planning_context,
        default_studio_artifact_execution_strategy(request),
        None,
    )
    .await
}

pub async fn generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy(
    runtime_plan: StudioArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: Option<&StudioArtifactPlanningContext>,
    execution_strategy: StudioExecutionStrategy,
    progress_observer: Option<StudioArtifactGenerationProgressObserver>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        planning_context,
        execution_strategy,
        None,
        progress_observer,
    )
    .await
}

pub async fn generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_render_evaluator(
    runtime_plan: StudioArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: Option<&StudioArtifactPlanningContext>,
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
        runtime_plan,
        title,
        intent,
        request,
        refinement,
        planning_context,
        default_studio_artifact_execution_strategy(request),
        render_evaluator,
        None,
    )
    .await
}

pub async fn generate_studio_artifact_bundle_with_runtime_plan_and_planning_context_and_execution_strategy_and_render_evaluator(
    runtime_plan: StudioArtifactResolvedRuntimePlan,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    planning_context: Option<&StudioArtifactPlanningContext>,
    execution_strategy: StudioExecutionStrategy,
    render_evaluator: Option<&dyn StudioArtifactRenderEvaluator>,
    progress_observer: Option<StudioArtifactGenerationProgressObserver>,
) -> Result<StudioArtifactGenerationBundle, StudioArtifactGenerationError> {
    let planning_runtime = runtime_plan.planning_runtime.clone();
    let production_runtime = runtime_plan.generation_runtime.clone();
    let final_acceptance_runtime = runtime_plan.acceptance_runtime.clone();
    let repair_runtime = runtime_plan.repair_runtime.clone();
    let runtime_policy = runtime_plan.policy.clone();
    let production_provenance = production_runtime.studio_runtime_provenance();
    let acceptance_provenance = final_acceptance_runtime.studio_runtime_provenance();
    let repair_provenance = repair_runtime.studio_runtime_provenance();
    let model = runtime_model_label(&production_runtime);
    let repair_model = runtime_model_label(&repair_runtime);
    studio_generation_trace(format!(
        "artifact_generation:start renderer={:?} profile={:?} planning_model={:?} production_model={:?} acceptance_model={:?} repair_model={:?} refinement={}",
        request.renderer,
        runtime_policy.profile,
        planning_runtime.studio_runtime_provenance().model,
        production_provenance.model,
        acceptance_provenance.model,
        repair_provenance.model,
        refinement.is_some()
    ));
    let direct_author_mode = direct_authoring_enabled(execution_strategy, request, refinement);
    let planning_context = match planning_context {
        Some(existing) => existing.clone(),
        None if direct_author_mode => StudioArtifactPlanningContext {
            brief: direct_author_brief(title, intent),
            blueprint: None,
            artifact_ir: None,
            selected_skills: Vec::new(),
            retrieved_exemplars: Vec::new(),
        },
        None => {
            let brief = plan_studio_artifact_brief_with_runtime(
                planning_runtime.clone(),
                title,
                intent,
                request,
                refinement,
            )
            .await
            .map_err(|message| StudioArtifactGenerationError {
                message,
                brief: None,
                blueprint: None,
                artifact_ir: None,
                selected_skills: Vec::new(),
                edit_intent: None,
                candidate_summaries: Vec::new(),
            })?;
            derive_planning_context_for_request(request, &brief, None, None, Vec::new())
        }
    };
    let brief = planning_context.brief.clone();
    studio_generation_trace("artifact_generation:brief_ready");
    let blueprint = planning_context.blueprint.clone();
    let artifact_ir = planning_context.artifact_ir.clone();
    let selected_skills = planning_context.selected_skills.clone();
    let retrieved_exemplars = planning_context.retrieved_exemplars.clone();
    let edit_intent = if direct_author_mode {
        None
    } else {
        match refinement {
            Some(refinement) => Some(hydrate_edit_intent_with_refinement_selection(
                plan_studio_artifact_edit_intent_with_runtime(
                    planning_runtime.clone(),
                    intent,
                    request,
                    &brief,
                    refinement,
                )
                .await
                .map_err(|message| StudioArtifactGenerationError {
                    message,
                    brief: Some(brief.clone()),
                    blueprint: blueprint.clone(),
                    artifact_ir: artifact_ir.clone(),
                    selected_skills: selected_skills.clone(),
                    edit_intent: None,
                    candidate_summaries: Vec::new(),
                })?,
                refinement,
            )),
            None => None,
        }
    };
    studio_generation_trace(format!(
        "artifact_generation:edit_intent_ready present={}",
        edit_intent.is_some()
    ));
    studio_generation_trace(format!(
        "artifact_generation:execution_strategy {:?}",
        execution_strategy
    ));
    if studio_artifact_uses_swarm_execution(execution_strategy) {
        warm_local_html_generation_runtime_if_needed(
            request,
            &planning_runtime,
            &production_runtime,
        )
        .await;
        return generate_studio_artifact_bundle_with_swarm(
            runtime_plan.clone(),
            title,
            intent,
            request,
            refinement,
            &brief,
            blueprint.as_ref(),
            artifact_ir.as_ref(),
            &selected_skills,
            &retrieved_exemplars,
            edit_intent.as_ref(),
            execution_strategy,
            render_evaluator,
            progress_observer,
        )
        .await;
    }

    let origin = output_origin_from_provenance(&production_provenance);
    let (_, configured_temperature, candidate_strategy) =
        candidate_generation_config(request.renderer, production_provenance.kind);
    let strategy = if direct_author_mode {
        "direct_author"
    } else {
        candidate_strategy
    };
    let temperature = if direct_author_mode {
        effective_direct_author_temperature(
            request.renderer,
            production_provenance.kind,
            configured_temperature,
        )
    } else {
        effective_candidate_generation_temperature(
            request.renderer,
            production_provenance.kind,
            configured_temperature,
        )
    };
    let mut adaptive_search_budget = if direct_author_mode {
        direct_author_search_budget(request, production_provenance.kind)
    } else {
        derive_studio_adaptive_search_budget(
            request,
            &brief,
            blueprint.as_ref(),
            artifact_ir.as_ref(),
            &selected_skills,
            &retrieved_exemplars,
            refinement,
            production_provenance.kind,
            runtime_policy.profile,
            !studio_runtime_provenance_matches(&acceptance_provenance, &production_provenance),
        )
    };
    studio_generation_trace(format!(
        "artifact_generation:candidate_config initial_count={} max_count={} shortlist_limit={} max_refine={} temperature={} configured_temperature={} strategy={}",
        adaptive_search_budget.initial_candidate_count,
        adaptive_search_budget.max_candidate_count,
        adaptive_search_budget.shortlist_limit,
        adaptive_search_budget.max_semantic_refinement_passes,
        temperature,
        configured_temperature,
        strategy
    ));
    let live_preview_state = Arc::new(Mutex::new(Vec::<ExecutionLivePreview>::new()));
    if direct_author_mode {
        emit_non_swarm_generation_progress(
            progress_observer.as_ref(),
            request,
            execution_strategy,
            &snapshot_execution_live_previews(&live_preview_state),
            "Authoring artifact directly...",
            None,
            None,
            ExecutionCompletionInvariantStatus::Pending,
            Vec::new(),
        );
    }
    let mut candidate_rows = Vec::<(
        StudioArtifactCandidateSummary,
        StudioGeneratedArtifactPayload,
    )>::new();
    let mut failed_candidate_summaries = Vec::<StudioArtifactCandidateSummary>::new();
    let mut candidate_generation_errors = Vec::<String>::new();
    let mut next_candidate_index = 0usize;
    let mut target_candidate_count = adaptive_search_budget.initial_candidate_count.max(1);
    let (mut candidate_summaries, ranked_candidate_indices) = loop {
        while next_candidate_index < target_candidate_count {
            let candidate_id = format!("candidate-{}", next_candidate_index + 1);
            let seed = candidate_seed_for(title, intent, next_candidate_index);
            let candidate_result = if direct_author_mode {
                let direct_live_preview_observer: Option<StudioArtifactLivePreviewObserver> =
                    progress_observer.as_ref().map(|_| {
                        let progress_observer = progress_observer.clone();
                        let direct_request = request.clone();
                        let live_preview_state = live_preview_state.clone();
                        Arc::new(move |preview: ExecutionLivePreview| {
                            if let Ok(mut previews) = live_preview_state.lock() {
                                upsert_execution_live_preview(&mut previews, preview.clone());
                            }
                            let live_previews =
                                snapshot_execution_live_previews(&live_preview_state);
                            emit_non_swarm_generation_progress(
                                progress_observer.as_ref(),
                                &direct_request,
                                StudioExecutionStrategy::DirectAuthor,
                                &live_previews,
                                format!("Streaming {}.", preview.label),
                                None,
                                None,
                                ExecutionCompletionInvariantStatus::Pending,
                                Vec::new(),
                            );
                        }) as StudioArtifactLivePreviewObserver
                    });
                let payload =
                    materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
                        production_runtime.clone(),
                        Some(repair_runtime.clone()),
                        title,
                        intent,
                        request,
                        &brief,
                        refinement,
                        &candidate_id,
                        seed,
                        temperature,
                        direct_live_preview_observer,
                    )
                    .await;
                match payload {
                    Ok(payload) => {
                        if let Some(preview) =
                            non_swarm_canonical_preview(request, &payload, "draft_ready", false)
                        {
                            if let Ok(mut previews) = live_preview_state.lock() {
                                upsert_execution_live_preview(&mut previews, preview);
                            }
                        }
                        emit_non_swarm_generation_progress(
                            progress_observer.as_ref(),
                            request,
                            execution_strategy,
                            &snapshot_execution_live_previews(&live_preview_state),
                            "Direct-authored draft landed. Evaluating rendered artifact...",
                            None,
                            None,
                            ExecutionCompletionInvariantStatus::Pending,
                            non_swarm_required_artifact_paths(&payload),
                        );
                        let render_evaluation = if direct_author_should_defer_render_evaluation(
                            request,
                            production_provenance.kind,
                        ) {
                            None
                        } else {
                            evaluate_candidate_render_with_fallback(
                                render_evaluator,
                                request,
                                &brief,
                                None,
                                None,
                                None,
                                &payload,
                                production_provenance.kind,
                            )
                            .await
                        };
                        emit_non_swarm_generation_progress(
                            progress_observer.as_ref(),
                            request,
                            execution_strategy,
                            &snapshot_execution_live_previews(&live_preview_state),
                            if render_evaluation.is_some() {
                                "Render evaluation complete. Preparing acceptance verification..."
                            } else {
                                "Draft landed. Deferring render capture and preparing acceptance verification..."
                            },
                            render_evaluation.as_ref(),
                            None,
                            ExecutionCompletionInvariantStatus::Pending,
                            non_swarm_required_artifact_paths(&payload),
                        );
                        let judge = direct_author_provisional_candidate_judge(
                            &payload,
                            render_evaluation.as_ref(),
                        );
                        Ok((
                            StudioArtifactCandidateSummary {
                                candidate_id: candidate_id.clone(),
                                seed,
                                model: model.to_string(),
                                temperature,
                                strategy: strategy.to_string(),
                                origin,
                                provenance: Some(production_provenance.clone()),
                                summary: payload.summary.clone(),
                                renderable_paths: payload
                                    .files
                                    .iter()
                                    .filter(|file| file.renderable)
                                    .map(|file| file.path.clone())
                                    .collect(),
                                selected: false,
                                fallback: false,
                                failure: None,
                                raw_output_preview: None,
                                convergence: Some(initial_candidate_convergence_trace(
                                    &candidate_id,
                                    "direct_author",
                                    judge_total_score(&judge),
                                )),
                                render_evaluation,
                                judge,
                            },
                            payload,
                        ))
                    }
                    Err(error) => Err(StudioArtifactCandidateSummary {
                        candidate_id: candidate_id.clone(),
                        seed,
                        model: model.to_string(),
                        temperature,
                        strategy: strategy.to_string(),
                        origin,
                        provenance: Some(production_provenance.clone()),
                        summary: "Direct authoring failed during materialization.".to_string(),
                        renderable_paths: Vec::new(),
                        selected: false,
                        fallback: false,
                        failure: Some(error.message.clone()),
                        raw_output_preview: error.raw_output_preview.clone(),
                        convergence: Some(initial_candidate_convergence_trace(
                            &candidate_id,
                            "direct_author_failure",
                            judge_total_score(&blocked_candidate_generation_judge(&error.message)),
                        )),
                        render_evaluation: None,
                        judge: blocked_candidate_generation_judge(&error.message),
                    }),
                }
            } else {
                materialize_and_locally_judge_candidate(
                    production_runtime.clone(),
                    repair_runtime.clone(),
                    render_evaluator,
                    title,
                    intent,
                    request,
                    &brief,
                    blueprint.as_ref(),
                    artifact_ir.as_ref(),
                    &selected_skills,
                    &retrieved_exemplars,
                    edit_intent.as_ref(),
                    refinement,
                    &candidate_id,
                    seed,
                    temperature,
                    strategy,
                    origin,
                    &model,
                    &production_provenance,
                )
                .await
            };
            match candidate_result {
                Ok((summary, payload)) => candidate_rows.push((summary, payload)),
                Err(summary) => {
                    if let Some(failure) = summary.failure.clone() {
                        candidate_generation_errors
                            .push(format!("{}: {}", summary.candidate_id, failure));
                    }
                    failed_candidate_summaries.push(summary);
                }
            }
            next_candidate_index += 1;
        }

        if candidate_rows.is_empty() {
            if target_candidate_count < adaptive_search_budget.max_candidate_count {
                record_adaptive_search_signal(
                    &mut adaptive_search_budget.signals,
                    StudioAdaptiveSearchSignal::GenerationFailureObserved,
                );
                target_candidate_count = adaptive_search_budget.max_candidate_count;
                studio_generation_trace(format!(
                    "artifact_generation:adaptive_search_expand reason=failures_only target={}",
                    target_candidate_count
                ));
                continue;
            }
            return Err(StudioArtifactGenerationError {
                message: if candidate_generation_errors.is_empty() {
                    "Studio artifact generation did not produce any candidates.".to_string()
                } else {
                    format!(
                        "Studio artifact generation did not produce a valid candidate. {}",
                        candidate_generation_errors.join(" | ")
                    )
                },
                brief: Some(brief),
                blueprint,
                artifact_ir,
                selected_skills,
                edit_intent,
                candidate_summaries: failed_candidate_summaries,
            });
        }

        let candidate_summaries = candidate_rows
            .iter()
            .map(|(summary, _)| summary.clone())
            .collect::<Vec<_>>();
        let ranked_candidate_indices = ranked_candidate_indices_by_score(&candidate_summaries);
        let expanded_target = target_candidate_count_after_initial_search(
            &mut adaptive_search_budget,
            &ranked_candidate_indices,
            &candidate_summaries,
            failed_candidate_summaries.len(),
        );
        if expanded_target > target_candidate_count {
            studio_generation_trace(format!(
                "artifact_generation:adaptive_search_expand from={} to={} signals={:?}",
                target_candidate_count, expanded_target, adaptive_search_budget.signals
            ));
            target_candidate_count = expanded_target;
            continue;
        }
        break (candidate_summaries, ranked_candidate_indices);
    };
    let shortlisted_candidate_indices = shortlisted_candidate_indices_for_budget(
        &mut adaptive_search_budget,
        &ranked_candidate_indices,
        &candidate_summaries,
    );
    studio_generation_trace(format!(
        "artifact_generation:shortlist size={} limit={} signals={:?}",
        shortlisted_candidate_indices.len(),
        adaptive_search_budget.shortlist_limit,
        adaptive_search_budget.signals
    ));

    if !direct_author_mode
        && local_draft_fast_path_enabled(
            request,
            refinement,
            &production_provenance,
            &acceptance_provenance,
        )
    {
        if let Some(winner_index) = ranked_candidate_indices.iter().copied().find(|index| {
            candidate_summaries
                .get(*index)
                .map(|summary| judge_supports_local_draft_surface(&summary.judge))
                .unwrap_or(false)
        }) {
            studio_generation_trace(format!(
                "artifact_generation:local_draft_fast_path winner={}",
                candidate_summaries
                    .get(winner_index)
                    .map(|summary| summary.candidate_id.as_str())
                    .unwrap_or("missing")
            ));
            let draft_judge = candidate_summaries
                .get(winner_index)
                .map(|summary| local_draft_pending_acceptance_judge(&summary.judge, None, None))
                .ok_or_else(|| StudioArtifactGenerationError {
                    message: "Studio winning draft candidate summary is missing.".to_string(),
                    brief: Some(brief.clone()),
                    blueprint: blueprint.clone(),
                    artifact_ir: artifact_ir.clone(),
                    selected_skills: selected_skills.clone(),
                    edit_intent: edit_intent.clone(),
                    candidate_summaries: merged_candidate_summaries(
                        &candidate_summaries,
                        &failed_candidate_summaries,
                    ),
                })?;

            return build_non_swarm_draft_bundle(
                request,
                brief,
                blueprint,
                artifact_ir,
                selected_skills,
                edit_intent,
                candidate_summaries,
                &failed_candidate_summaries,
                &candidate_rows,
                winner_index,
                draft_judge,
                "draft_surface_pending_acceptance",
                execution_strategy,
                origin,
                production_provenance,
                acceptance_provenance,
                runtime_policy.clone(),
                adaptive_search_budget.clone(),
                refinement.and_then(|context| context.taste_memory.clone()),
                &snapshot_execution_live_previews(&live_preview_state),
            );
        }
    }

    let acceptance_timeout =
        acceptance_timeout_for_execution_strategy(execution_strategy, &final_acceptance_runtime);
    let mut evaluated_acceptance_indices = std::collections::HashSet::<usize>::new();
    let mut refined_candidate_roots = std::collections::HashSet::<String>::new();
    let mut best_acceptance_index = None;
    let mut best_acceptance_score = i32::MIN;
    let mut selected_winner_index = None;

    for candidate_index in shortlisted_candidate_indices {
        let candidate_id = candidate_summaries
            .get(candidate_index)
            .map(|summary| summary.candidate_id.clone())
            .unwrap_or_else(|| format!("candidate-index-{candidate_index}"));
        if direct_author_mode {
            emit_non_swarm_generation_progress(
                progress_observer.as_ref(),
                request,
                execution_strategy,
                &snapshot_execution_live_previews(&live_preview_state),
                "Running acceptance verification for the direct-authored draft...",
                candidate_summaries
                    .get(candidate_index)
                    .and_then(|summary| summary.render_evaluation.as_ref()),
                None,
                ExecutionCompletionInvariantStatus::Pending,
                non_swarm_required_artifact_paths(&candidate_rows[candidate_index].1),
            );
        }
        studio_generation_trace(format!(
            "artifact_generation:acceptance:start id={}",
            candidate_id
        ));
        let acceptance_judge = match judge_candidate_with_runtime_and_render_eval_with_timeout(
            final_acceptance_runtime.clone(),
            acceptance_timeout,
            candidate_summaries
                .get(candidate_index)
                .and_then(|summary| summary.render_evaluation.as_ref()),
            title,
            request,
            &brief,
            edit_intent.as_ref(),
            &candidate_rows[candidate_index].1,
        )
        .await
        {
            Ok(judge) => judge,
            Err(message)
                if acceptance_timeout.is_some()
                    && message.contains("Acceptance judging timed out")
                    && direct_author_mode =>
            {
                let draft_index = std::iter::once(candidate_index)
                    .chain(ranked_candidate_indices.iter().copied())
                    .find(|index| {
                        candidate_summaries
                            .get(*index)
                            .map(candidate_supports_pending_draft_surface)
                            .unwrap_or(false)
                    });
                if let Some(winner_index) = draft_index {
                    studio_generation_trace(format!(
                        "artifact_generation:acceptance_timeout_fallback winner={} message={}",
                        candidate_summaries
                            .get(winner_index)
                            .map(|summary| summary.candidate_id.as_str())
                            .unwrap_or("missing"),
                        message
                    ));
                    let draft_judge = candidate_summaries
                        .get(winner_index)
                        .map(|summary| {
                            local_draft_pending_acceptance_judge(
                                &summary.judge,
                                Some(message.clone()),
                                Some(format!(
                                    "Studio kept a viable direct-authored draft available after {}",
                                    message.to_ascii_lowercase()
                                )),
                            )
                        })
                        .ok_or_else(|| StudioArtifactGenerationError {
                            message: "Studio winning draft candidate summary is missing."
                                .to_string(),
                            brief: Some(brief.clone()),
                            blueprint: blueprint.clone(),
                            artifact_ir: artifact_ir.clone(),
                            selected_skills: selected_skills.clone(),
                            edit_intent: edit_intent.clone(),
                            candidate_summaries: merged_candidate_summaries(
                                &candidate_summaries,
                                &failed_candidate_summaries,
                            ),
                        })?;
                    return build_non_swarm_draft_bundle(
                        request,
                        brief.clone(),
                        blueprint.clone(),
                        artifact_ir.clone(),
                        selected_skills.clone(),
                        edit_intent.clone(),
                        candidate_summaries.clone(),
                        &failed_candidate_summaries,
                        &candidate_rows,
                        winner_index,
                        draft_judge,
                        "draft_surface_acceptance_timeout",
                        execution_strategy,
                        origin,
                        production_provenance.clone(),
                        acceptance_provenance.clone(),
                        runtime_policy.clone(),
                        adaptive_search_budget.clone(),
                        refinement.and_then(|context| context.taste_memory.clone()),
                        &snapshot_execution_live_previews(&live_preview_state),
                    );
                }
                return Err(StudioArtifactGenerationError {
                    message,
                    brief: Some(brief.clone()),
                    blueprint: blueprint.clone(),
                    artifact_ir: artifact_ir.clone(),
                    selected_skills: selected_skills.clone(),
                    edit_intent: edit_intent.clone(),
                    candidate_summaries: candidate_summaries.clone(),
                });
            }
            Err(message) => {
                return Err(StudioArtifactGenerationError {
                    message,
                    brief: Some(brief.clone()),
                    blueprint: blueprint.clone(),
                    artifact_ir: artifact_ir.clone(),
                    selected_skills: selected_skills.clone(),
                    edit_intent: edit_intent.clone(),
                    candidate_summaries: candidate_summaries.clone(),
                });
            }
        };
        studio_generation_trace(format!(
            "artifact_generation:acceptance:ok id={} classification={:?}",
            candidate_id, acceptance_judge.classification
        ));
        if direct_author_mode {
            emit_non_swarm_generation_progress(
                progress_observer.as_ref(),
                request,
                execution_strategy,
                &snapshot_execution_live_previews(&live_preview_state),
                format!(
                    "Acceptance judge returned {}.",
                    judge_classification_id(acceptance_judge.classification)
                ),
                candidate_summaries
                    .get(candidate_index)
                    .and_then(|summary| summary.render_evaluation.as_ref()),
                Some(&acceptance_judge),
                if judge_clears_primary_view(&acceptance_judge) {
                    ExecutionCompletionInvariantStatus::Satisfied
                } else {
                    ExecutionCompletionInvariantStatus::Blocked
                },
                non_swarm_required_artifact_paths(&candidate_rows[candidate_index].1),
            );
        }
        evaluated_acceptance_indices.insert(candidate_index);
        if let Some(summary) = candidate_summaries.get_mut(candidate_index) {
            update_candidate_summary_judge(summary, acceptance_judge.clone());
        }
        let acceptance_score = judge_total_score(&acceptance_judge);
        if acceptance_score > best_acceptance_score {
            best_acceptance_score = acceptance_score;
            best_acceptance_index = Some(candidate_index);
        }
        if judge_clears_primary_view(&acceptance_judge) {
            selected_winner_index = Some(candidate_index);
            break;
        }
    }

    if selected_winner_index.is_none()
        && renderer_supports_semantic_refinement(request.renderer)
        && best_acceptance_index.is_some()
    {
        let progress = attempt_semantic_refinement_for_candidate(
            repair_runtime.clone(),
            final_acceptance_runtime.clone(),
            render_evaluator,
            title,
            intent,
            request,
            &brief,
            blueprint.as_ref(),
            artifact_ir.as_ref(),
            &selected_skills,
            &retrieved_exemplars,
            edit_intent.as_ref(),
            refinement,
            strategy,
            origin,
            &repair_model,
            &repair_provenance,
            &adaptive_search_budget,
            best_acceptance_index.expect("best acceptance index"),
            &mut candidate_rows,
            &mut candidate_summaries,
            &mut refined_candidate_roots,
            best_acceptance_index,
            best_acceptance_score,
        )
        .await?;
        best_acceptance_index = progress.best_acceptance_index;
        best_acceptance_score = progress.best_acceptance_score;
        selected_winner_index = progress.selected_winner_index;
    }

    if selected_winner_index.is_none() {
        for candidate_index in ranked_candidate_indices.iter().copied() {
            if evaluated_acceptance_indices.contains(&candidate_index) {
                continue;
            }
            let candidate_id = candidate_summaries
                .get(candidate_index)
                .map(|summary| summary.candidate_id.clone())
                .unwrap_or_else(|| format!("candidate-index-{candidate_index}"));
            if direct_author_mode {
                emit_non_swarm_generation_progress(
                    progress_observer.as_ref(),
                    request,
                    execution_strategy,
                    &snapshot_execution_live_previews(&live_preview_state),
                    "Running fallback acceptance verification for the direct-authored draft...",
                    candidate_summaries
                        .get(candidate_index)
                        .and_then(|summary| summary.render_evaluation.as_ref()),
                    None,
                    ExecutionCompletionInvariantStatus::Pending,
                    non_swarm_required_artifact_paths(&candidate_rows[candidate_index].1),
                );
            }
            studio_generation_trace(format!(
                "artifact_generation:acceptance_fallback:start id={}",
                candidate_id
            ));
            let acceptance_judge = match judge_candidate_with_runtime_and_render_eval_with_timeout(
                final_acceptance_runtime.clone(),
                acceptance_timeout,
                candidate_summaries
                    .get(candidate_index)
                    .and_then(|summary| summary.render_evaluation.as_ref()),
                title,
                request,
                &brief,
                edit_intent.as_ref(),
                &candidate_rows[candidate_index].1,
            )
            .await
            {
                Ok(judge) => judge,
                Err(message)
                    if acceptance_timeout.is_some()
                        && message.contains("Acceptance judging timed out")
                        && direct_author_mode =>
                {
                    let draft_index = std::iter::once(candidate_index)
                        .chain(ranked_candidate_indices.iter().copied())
                        .find(|index| {
                            candidate_summaries
                                .get(*index)
                                .map(candidate_supports_pending_draft_surface)
                                .unwrap_or(false)
                        });
                    if let Some(winner_index) = draft_index {
                        studio_generation_trace(format!(
                            "artifact_generation:acceptance_timeout_fallback winner={} message={}",
                            candidate_summaries
                                .get(winner_index)
                                .map(|summary| summary.candidate_id.as_str())
                                .unwrap_or("missing"),
                            message
                        ));
                        let draft_judge = candidate_summaries
                            .get(winner_index)
                            .map(|summary| {
                                local_draft_pending_acceptance_judge(
                                    &summary.judge,
                                    Some(message.clone()),
                                    Some(format!(
                                        "Studio kept a viable direct-authored draft available after {}",
                                        message.to_ascii_lowercase()
                                    )),
                                )
                            })
                            .ok_or_else(|| StudioArtifactGenerationError {
                                message: "Studio winning draft candidate summary is missing."
                                    .to_string(),
                                brief: Some(brief.clone()),
                                blueprint: blueprint.clone(),
                                artifact_ir: artifact_ir.clone(),
                                selected_skills: selected_skills.clone(),
                                edit_intent: edit_intent.clone(),
                                candidate_summaries: merged_candidate_summaries(
                                    &candidate_summaries,
                                    &failed_candidate_summaries,
                                ),
                            })?;
                        return build_non_swarm_draft_bundle(
                            request,
                            brief.clone(),
                            blueprint.clone(),
                            artifact_ir.clone(),
                            selected_skills.clone(),
                            edit_intent.clone(),
                            candidate_summaries.clone(),
                            &failed_candidate_summaries,
                            &candidate_rows,
                            winner_index,
                            draft_judge,
                            "draft_surface_acceptance_timeout",
                            execution_strategy,
                            origin,
                            production_provenance.clone(),
                            acceptance_provenance.clone(),
                            runtime_policy.clone(),
                            adaptive_search_budget.clone(),
                            refinement.and_then(|context| context.taste_memory.clone()),
                            &snapshot_execution_live_previews(&live_preview_state),
                        );
                    }
                    return Err(StudioArtifactGenerationError {
                        message,
                        brief: Some(brief.clone()),
                        blueprint: blueprint.clone(),
                        artifact_ir: artifact_ir.clone(),
                        selected_skills: selected_skills.clone(),
                        edit_intent: edit_intent.clone(),
                        candidate_summaries: merged_candidate_summaries(
                            &candidate_summaries,
                            &failed_candidate_summaries,
                        ),
                    });
                }
                Err(message) => {
                    return Err(StudioArtifactGenerationError {
                        message,
                        brief: Some(brief.clone()),
                        blueprint: blueprint.clone(),
                        artifact_ir: artifact_ir.clone(),
                        selected_skills: selected_skills.clone(),
                        edit_intent: edit_intent.clone(),
                        candidate_summaries: merged_candidate_summaries(
                            &candidate_summaries,
                            &failed_candidate_summaries,
                        ),
                    });
                }
            };
            studio_generation_trace(format!(
                "artifact_generation:acceptance_fallback:ok id={} classification={:?}",
                candidate_id, acceptance_judge.classification
            ));
            if direct_author_mode {
                emit_non_swarm_generation_progress(
                    progress_observer.as_ref(),
                    request,
                    execution_strategy,
                    &snapshot_execution_live_previews(&live_preview_state),
                    format!(
                        "Fallback acceptance judge returned {}.",
                        judge_classification_id(acceptance_judge.classification)
                    ),
                    candidate_summaries
                        .get(candidate_index)
                        .and_then(|summary| summary.render_evaluation.as_ref()),
                    Some(&acceptance_judge),
                    if judge_clears_primary_view(&acceptance_judge) {
                        ExecutionCompletionInvariantStatus::Satisfied
                    } else {
                        ExecutionCompletionInvariantStatus::Blocked
                    },
                    non_swarm_required_artifact_paths(&candidate_rows[candidate_index].1),
                );
            }
            evaluated_acceptance_indices.insert(candidate_index);
            if let Some(summary) = candidate_summaries.get_mut(candidate_index) {
                update_candidate_summary_judge(summary, acceptance_judge.clone());
            }
            let acceptance_score = judge_total_score(&acceptance_judge);
            if acceptance_score > best_acceptance_score {
                best_acceptance_score = acceptance_score;
                best_acceptance_index = Some(candidate_index);
            }
            if judge_clears_primary_view(&acceptance_judge) {
                selected_winner_index = Some(candidate_index);
                break;
            }
            if renderer_supports_semantic_refinement(request.renderer) {
                let progress = attempt_semantic_refinement_for_candidate(
                    repair_runtime.clone(),
                    final_acceptance_runtime.clone(),
                    render_evaluator,
                    title,
                    intent,
                    request,
                    &brief,
                    blueprint.as_ref(),
                    artifact_ir.as_ref(),
                    &selected_skills,
                    &retrieved_exemplars,
                    edit_intent.as_ref(),
                    refinement,
                    strategy,
                    origin,
                    &repair_model,
                    &repair_provenance,
                    &adaptive_search_budget,
                    candidate_index,
                    &mut candidate_rows,
                    &mut candidate_summaries,
                    &mut refined_candidate_roots,
                    best_acceptance_index,
                    best_acceptance_score,
                )
                .await?;
                best_acceptance_index = progress.best_acceptance_index;
                best_acceptance_score = progress.best_acceptance_score;
                if let Some(winner_index) = progress.selected_winner_index {
                    selected_winner_index = Some(winner_index);
                    break;
                }
            }
        }
    }

    let winner_index = selected_winner_index
        .or(best_acceptance_index)
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio winning candidate summary is missing.".to_string(),
            brief: Some(brief.clone()),
            blueprint: blueprint.clone(),
            artifact_ir: artifact_ir.clone(),
            selected_skills: selected_skills.clone(),
            edit_intent: edit_intent.clone(),
            candidate_summaries: merged_candidate_summaries(
                &candidate_summaries,
                &failed_candidate_summaries,
            ),
        })?;
    if let Some(selected) = candidate_summaries.get_mut(winner_index) {
        selected.selected = true;
        let termination = if selected_winner_index == Some(winner_index) {
            "selected_after_primary_view_clear"
        } else {
            "selected_as_best_available_candidate"
        };
        set_candidate_termination_reason(selected, termination);
    }
    let winner_summary = candidate_summaries
        .get(winner_index)
        .cloned()
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio winning candidate summary is missing.".to_string(),
            brief: Some(brief.clone()),
            blueprint: blueprint.clone(),
            artifact_ir: artifact_ir.clone(),
            selected_skills: selected_skills.clone(),
            edit_intent: edit_intent.clone(),
            candidate_summaries: merged_candidate_summaries(
                &candidate_summaries,
                &failed_candidate_summaries,
            ),
        })?;
    let acceptance_judge = winner_summary.judge.clone();
    let winner = candidate_rows
        .into_iter()
        .nth(winner_index)
        .map(|(_, payload)| payload)
        .ok_or_else(|| StudioArtifactGenerationError {
            message: "Studio winning artifact payload is missing.".to_string(),
            brief: Some(brief.clone()),
            blueprint: blueprint.clone(),
            artifact_ir: artifact_ir.clone(),
            selected_skills: selected_skills.clone(),
            edit_intent: edit_intent.clone(),
            candidate_summaries: merged_candidate_summaries(
                &candidate_summaries,
                &failed_candidate_summaries,
            ),
        })?;
    let final_candidate_summaries =
        merged_candidate_summaries(&candidate_summaries, &failed_candidate_summaries);
    studio_generation_trace(format!(
        "artifact_generation:winner id={}",
        winner_summary.candidate_id
    ));
    if let Some(preview) = non_swarm_canonical_preview(request, &winner, "completed", true) {
        if let Ok(mut previews) = live_preview_state.lock() {
            upsert_execution_live_preview(&mut previews, preview);
        }
    }
    let execution_envelope = build_non_swarm_execution_envelope(
        request,
        execution_strategy,
        &snapshot_execution_live_previews(&live_preview_state),
        if judge_clears_primary_view(&acceptance_judge) {
            ExecutionCompletionInvariantStatus::Satisfied
        } else {
            ExecutionCompletionInvariantStatus::Blocked
        },
        non_swarm_required_artifact_paths(&winner),
    );

    Ok(StudioArtifactGenerationBundle {
        brief,
        blueprint,
        artifact_ir,
        selected_skills,
        edit_intent,
        candidate_summaries: final_candidate_summaries,
        winning_candidate_id: Some(winner_summary.candidate_id.clone()),
        winning_candidate_rationale: Some(winner_summary.judge.rationale.clone()),
        execution_envelope,
        swarm_plan: None,
        swarm_execution: None,
        swarm_worker_receipts: Vec::new(),
        swarm_change_receipts: Vec::new(),
        swarm_merge_receipts: Vec::new(),
        swarm_verification_receipts: Vec::new(),
        judge: acceptance_judge,
        winner,
        render_evaluation: winner_summary.render_evaluation.clone(),
        origin,
        production_provenance,
        acceptance_provenance,
        runtime_policy: Some(runtime_policy),
        adaptive_search_budget: Some(adaptive_search_budget),
        fallback_used: false,
        ux_lifecycle: StudioArtifactUxLifecycle::Judged,
        taste_memory: refinement.and_then(|context| context.taste_memory.clone()),
        failure: None,
    })
}

fn hydrate_edit_intent_with_refinement_selection(
    mut edit_intent: StudioArtifactEditIntent,
    refinement: &StudioArtifactRefinementContext,
) -> StudioArtifactEditIntent {
    if edit_intent.selected_targets.is_empty() && !refinement.selected_targets.is_empty() {
        edit_intent.selected_targets = refinement.selected_targets.clone();
    }
    if edit_intent.target_paths.is_empty() {
        let mut target_paths = edit_intent
            .selected_targets
            .iter()
            .filter_map(|target| target.path.clone())
            .collect::<Vec<_>>();
        target_paths.sort();
        target_paths.dedup();
        edit_intent.target_paths = target_paths;
    }
    edit_intent
}

pub async fn materialize_studio_artifact_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
) -> Result<StudioGeneratedArtifactPayload, String> {
    materialize_studio_artifact_candidate_with_runtime(
        runtime,
        title,
        intent,
        request,
        &StudioArtifactBrief {
            audience: "general audience".to_string(),
            job_to_be_done: "deliver the requested artifact".to_string(),
            subject_domain: title.to_string(),
            artifact_thesis: intent.to_string(),
            required_concepts: Vec::new(),
            required_interactions: Vec::new(),
            visual_tone: Vec::new(),
            factual_anchors: Vec::new(),
            style_directives: Vec::new(),
            reference_hints: Vec::new(),
        },
        None,
        None,
        "candidate-1",
        candidate_seed_for(title, intent, 0),
        0.0,
    )
    .await
}

async fn materialize_studio_artifact_candidate_with_runtime_detailed(
    runtime: Arc<dyn InferenceRuntime>,
    repair_runtime: Option<Arc<dyn InferenceRuntime>>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    temperature: f32,
) -> Result<StudioGeneratedArtifactPayload, StudioCandidateMaterializationError> {
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    let parse_candidate = |raw: &str| -> Result<
        StudioGeneratedArtifactPayload,
        StudioCandidateMaterializationError,
    > {
        let mut generated = super::parse_and_validate_generated_artifact_payload(raw, request)?;
        trace_html_contract_state(
            "artifact_generation:materialization_contract_state:parsed",
            request,
            candidate_id,
            &generated,
        );
        super::enrich_generated_artifact_payload(&mut generated, request, brief);
        trace_html_contract_state(
            "artifact_generation:materialization_contract_state:enriched",
            request,
            candidate_id,
            &generated,
        );
        super::validate_generated_artifact_payload_against_brief_with_edit_intent(
            &generated,
            request,
            brief,
            edit_intent,
        )?;
        Ok(generated)
    };
    let payload = build_studio_artifact_materialization_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        blueprint,
        artifact_ir,
        selected_skills,
        retrieved_exemplars,
        edit_intent,
        refinement,
        candidate_id,
        candidate_seed,
        runtime_kind,
    )
    .map_err(|message| StudioCandidateMaterializationError {
        message,
        raw_output_preview: None,
    })?;
    let input =
        serde_json::to_vec(&payload).map_err(|error| StudioCandidateMaterializationError {
            message: format!(
                "Failed to encode Studio artifact materialization prompt: {}",
                error
            ),
            raw_output_preview: None,
        })?;
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    studio_generation_trace(format!(
        "artifact_generation:materialization_inference:start id={} prompt_bytes={} temperature={} max_tokens={}",
        candidate_id,
        input.len(),
        temperature,
        materialization_max_tokens_for_runtime(request.renderer, runtime_kind)
    ));
    let output = runtime
        .clone()
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature,
                json_mode: true,
                max_tokens: materialization_max_tokens_for_runtime(request.renderer, runtime_kind),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| StudioCandidateMaterializationError {
            message: format!(
                "Studio artifact materialization inference failed: {}",
                error
            ),
            raw_output_preview: None,
        })?;
    studio_generation_trace(format!(
        "artifact_generation:materialization_inference:ok id={} bytes={}",
        candidate_id,
        output.len()
    ));
    let raw = String::from_utf8(output).map_err(|error| StudioCandidateMaterializationError {
        message: format!(
            "Studio artifact materialization utf8 decode failed: {}",
            error
        ),
        raw_output_preview: None,
    })?;
    match parse_candidate(&raw) {
        Ok(generated) => Ok(generated),
        Err(first_error) => {
            studio_generation_trace(format!(
                "artifact_generation:materialization_parse_error id={} error={} preview={}",
                candidate_id,
                first_error.message,
                truncate_candidate_failure_preview(&raw, 4000)
                    .unwrap_or_else(|| "(empty)".to_string())
            ));
            let mut latest_error = first_error.message;
            let mut latest_raw = raw;

            let repair_runtime = materialization_repair_runtime_for_request(
                request,
                &runtime,
                repair_runtime.as_ref(),
            );
            let repair_runtime_kind = repair_runtime.studio_runtime_provenance().kind;
            for repair_attempt in
                0..materialization_repair_pass_limit(request.renderer, repair_runtime_kind)
            {
                let repair_payload =
                    build_studio_artifact_materialization_repair_prompt_for_runtime(
                        title,
                        intent,
                        request,
                        brief,
                        blueprint,
                        artifact_ir,
                        selected_skills,
                        retrieved_exemplars,
                        edit_intent,
                        refinement,
                        candidate_id,
                        candidate_seed,
                        &latest_raw,
                        &latest_error,
                        repair_runtime_kind,
                    )
                    .map_err(|message| {
                        StudioCandidateMaterializationError {
                            message,
                            raw_output_preview: truncate_candidate_failure_preview(
                                &latest_raw,
                                2000,
                            ),
                        }
                    })?;
                let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                    StudioCandidateMaterializationError {
                        message: format!(
                            "Failed to encode Studio artifact materialization repair prompt: {}",
                            error
                        ),
                        raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                    }
                })?;
                studio_generation_trace(format!(
                    "artifact_generation:materialization_repair:start id={} attempt={} model={:?} prompt_bytes={} max_tokens={}",
                    candidate_id,
                    repair_attempt + 1,
                    repair_runtime.studio_runtime_provenance().model,
                    repair_input.len(),
                    materialization_max_tokens_for_runtime(
                        request.renderer,
                        repair_runtime_kind,
                    )
                ));
                let repair_output = repair_runtime
                    .execute_inference(
                        [0u8; 32],
                        &repair_input,
                        InferenceOptions {
                            temperature: 0.0,
                            json_mode: true,
                            max_tokens: materialization_max_tokens_for_runtime(
                                request.renderer,
                                repair_runtime_kind,
                            ),
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|error| StudioCandidateMaterializationError {
                        message: format!(
                            "{latest_error}; repair attempt {} inference failed: {error}",
                            repair_attempt + 1
                        ),
                        raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                    })?;
                studio_generation_trace(format!(
                    "artifact_generation:materialization_repair:ok id={} attempt={} bytes={}",
                    candidate_id,
                    repair_attempt + 1,
                    repair_output.len()
                ));
                let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                    StudioCandidateMaterializationError {
                        message: format!(
                            "{latest_error}; repair attempt {} utf8 decode failed: {error}",
                            repair_attempt + 1
                        ),
                        raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                    }
                })?;
                match parse_candidate(&repair_raw) {
                    Ok(generated) => return Ok(generated),
                    Err(repair_error) => {
                        studio_generation_trace(format!(
                            "artifact_generation:materialization_repair_parse_error id={} attempt={} error={} preview={}",
                            candidate_id,
                            repair_attempt + 1,
                            repair_error.message,
                            truncate_candidate_failure_preview(&repair_raw, 4000)
                                .unwrap_or_else(|| "(empty)".to_string())
                        ));
                        latest_raw = repair_raw;
                        latest_error = format!(
                            "{latest_error}; repair attempt {} failed: {}",
                            repair_attempt + 1,
                            repair_error.message
                        );
                    }
                }
            }

            Err(StudioCandidateMaterializationError {
                message: latest_error,
                raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
            })
        }
    }
}

pub(super) async fn materialize_studio_artifact_candidate_with_runtime_direct_author_detailed(
    runtime: Arc<dyn InferenceRuntime>,
    repair_runtime: Option<Arc<dyn InferenceRuntime>>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    temperature: f32,
    live_preview_observer: Option<StudioArtifactLivePreviewObserver>,
) -> Result<StudioGeneratedArtifactPayload, StudioCandidateMaterializationError> {
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    let returns_raw_document = direct_author_uses_raw_document(request);
    let max_tokens = materialization_max_tokens_for_execution_strategy(
        request.renderer,
        StudioExecutionStrategy::DirectAuthor,
        runtime_kind,
    );
    let parse_candidate = |raw: &str| -> Result<
        StudioGeneratedArtifactPayload,
        StudioCandidateMaterializationError,
    > {
        let mut generated = super::parse_and_validate_generated_artifact_payload(raw, request)?;
        trace_html_contract_state(
            "artifact_generation:direct_author_contract_state:parsed",
            request,
            candidate_id,
            &generated,
        );
        super::enrich_generated_artifact_payload(&mut generated, request, brief);
        trace_html_contract_state(
            "artifact_generation:direct_author_contract_state:enriched",
            request,
            candidate_id,
            &generated,
        );
        super::validate_generated_artifact_payload_against_brief_with_edit_intent(
            &generated, request, brief, None,
        )?;
        Ok(generated)
    };
    let payload = build_studio_artifact_direct_author_prompt_for_runtime(
        title,
        intent,
        request,
        refinement,
        candidate_id,
        candidate_seed,
        runtime_kind,
        returns_raw_document,
    )
    .map_err(|message| StudioCandidateMaterializationError {
        message,
        raw_output_preview: None,
    })?;
    let input =
        serde_json::to_vec(&payload).map_err(|error| StudioCandidateMaterializationError {
            message: format!(
                "Failed to encode Studio direct-author artifact prompt: {}",
                error
            ),
            raw_output_preview: None,
        })?;
    studio_generation_trace(format!(
        "artifact_generation:direct_author_inference:start id={} prompt_bytes={} temperature={} max_tokens={} raw_document={}",
        candidate_id,
        input.len(),
        temperature,
        max_tokens,
        returns_raw_document
    ));
    let preview_language = studio_swarm_preview_language(request);
    let preview_id = format!("{candidate_id}-live-output");
    let preview_label = "Direct author output".to_string();
    let (token_tx, collector) = spawn_token_stream_preview_collector(
        live_preview_observer.clone(),
        preview_id.clone(),
        preview_label.clone(),
        None,
        None,
        preview_language.clone(),
    );
    let token_stream = Some(token_tx);
    let stream_collector = Some(collector);
    let output_result = runtime
        .clone()
        .execute_inference_streaming(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature,
                json_mode: !returns_raw_document,
                max_tokens,
                stop_sequences: direct_author_stop_sequences(request),
                ..Default::default()
            },
            token_stream,
        )
        .await;
    let streamed_preview = finish_token_stream_preview_collector(stream_collector).await;
    let inference_error_message = output_result
        .as_ref()
        .err()
        .map(|error| format!("Studio direct-author artifact inference failed: {error}"));
    let recovered_from_partial_stream = output_result.is_err() && !streamed_preview.trim().is_empty();
    let raw = match output_result {
        Ok(output) => String::from_utf8(output).map_err(|error| StudioCandidateMaterializationError {
            message: format!(
                "Studio direct-author artifact utf8 decode failed: {}",
                error
            ),
            raw_output_preview: truncate_candidate_failure_preview(&streamed_preview, 2000),
        })?,
        Err(error) => {
            if streamed_preview.trim().is_empty() {
                return Err(StudioCandidateMaterializationError {
                    message: format!("Studio direct-author artifact inference failed: {}", error),
                    raw_output_preview: None,
                });
            }
            studio_generation_trace(format!(
                "artifact_generation:direct_author_inference:partial_stream_salvage id={} bytes={} error={}",
                candidate_id,
                streamed_preview.len(),
                error
            ));
            if let Some(observer) = live_preview_observer.as_ref() {
                observer(studio_swarm_live_preview(
                    preview_id.clone(),
                    ExecutionLivePreviewKind::TokenStream,
                    preview_label.clone(),
                    None,
                    None,
                    "interrupted",
                    preview_language.clone(),
                    live_token_stream_preview_text(&streamed_preview, 2200),
                    true,
                ));
            }
            streamed_preview.clone()
        }
    };
    match parse_candidate(&raw) {
        Ok(generated) => {
            if let Some(observer) = live_preview_observer.as_ref() {
                observer(studio_swarm_live_preview(
                    preview_id,
                    ExecutionLivePreviewKind::TokenStream,
                    preview_label,
                    None,
                    None,
                    if recovered_from_partial_stream {
                        "recovered"
                    } else {
                        "completed"
                    },
                    preview_language,
                    live_token_stream_preview_text(
                        if streamed_preview.trim().is_empty() {
                            &raw
                        } else {
                            &streamed_preview
                        },
                        2200,
                    ),
                    true,
                ));
            }
            Ok(generated)
        }
        Err(first_error) => {
            let mut latest_error = if let Some(inference_error) = inference_error_message {
                format!("{inference_error}; {}", first_error.message)
            } else {
                first_error.message
            };
            let mut latest_raw = raw;
            let repair_runtime = materialization_repair_runtime_for_request(
                request,
                &runtime,
                repair_runtime.as_ref(),
            );
            let repair_runtime_kind = repair_runtime.studio_runtime_provenance().kind;
            if returns_raw_document {
                for continuation_attempt in
                    0..direct_author_continuation_pass_limit(request, runtime_kind)
                {
                    if !direct_author_document_is_incomplete(request, &latest_raw, &latest_error) {
                        break;
                    }
                    let continuation_payload =
                        build_studio_artifact_direct_author_continuation_prompt_for_runtime(
                            title,
                            intent,
                            request,
                            &latest_raw,
                            &latest_error,
                            runtime_kind,
                        );
                    let continuation_input = serde_json::to_vec(&continuation_payload).map_err(
                        |error| StudioCandidateMaterializationError {
                            message: format!(
                                "Failed to encode Studio direct-author continuation prompt: {}",
                                error
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(
                                &latest_raw,
                                2000,
                            ),
                        },
                    )?;
                    let continuation_output = runtime
                        .clone()
                        .execute_inference(
                            [0u8; 32],
                            &continuation_input,
                            InferenceOptions {
                                temperature: 0.0,
                                json_mode: false,
                                max_tokens,
                                stop_sequences: direct_author_stop_sequences(request),
                                ..Default::default()
                            },
                        )
                        .await
                        .map_err(|error| StudioCandidateMaterializationError {
                            message: format!(
                                "{latest_error}; continuation attempt {} inference failed: {error}",
                                continuation_attempt + 1
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(
                                &latest_raw,
                                2000,
                            ),
                        })?;
                    let continuation_raw = String::from_utf8(continuation_output).map_err(
                        |error| StudioCandidateMaterializationError {
                            message: format!(
                                "{latest_error}; continuation attempt {} utf8 decode failed: {error}",
                                continuation_attempt + 1
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(
                                &latest_raw,
                                2000,
                            ),
                        },
                    )?;
                    latest_raw = merge_direct_author_document(&latest_raw, &continuation_raw);
                    match parse_candidate(&latest_raw) {
                        Ok(generated) => return Ok(generated),
                        Err(continuation_error) => {
                            latest_error = format!(
                                "{latest_error}; continuation attempt {} failed: {}",
                                continuation_attempt + 1,
                                continuation_error.message
                            );
                        }
                    }
                }
            }

            if returns_raw_document {
                for repair_attempt in
                    0..materialization_repair_pass_limit(request.renderer, repair_runtime_kind)
                {
                    let repair_payload =
                        build_studio_artifact_direct_author_repair_prompt_for_runtime(
                            title,
                            intent,
                            request,
                            &latest_raw,
                            &latest_error,
                            repair_runtime_kind,
                        );
                    let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                        StudioCandidateMaterializationError {
                            message: format!(
                                "Failed to encode Studio direct-author repair prompt: {}",
                                error
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                        }
                    })?;
                    let repair_output = repair_runtime
                        .execute_inference(
                            [0u8; 32],
                            &repair_input,
                            InferenceOptions {
                                temperature: 0.0,
                                json_mode: false,
                                max_tokens: materialization_max_tokens_for_execution_strategy(
                                    request.renderer,
                                    StudioExecutionStrategy::DirectAuthor,
                                    repair_runtime_kind,
                                ),
                                stop_sequences: direct_author_stop_sequences(request),
                                ..Default::default()
                            },
                        )
                        .await
                        .map_err(|error| StudioCandidateMaterializationError {
                            message: format!(
                                "{latest_error}; repair attempt {} inference failed: {error}",
                                repair_attempt + 1
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                        })?;
                    let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                        StudioCandidateMaterializationError {
                            message: format!(
                                "{latest_error}; repair attempt {} utf8 decode failed: {error}",
                                repair_attempt + 1
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                        }
                    })?;
                    match parse_candidate(&repair_raw) {
                        Ok(generated) => return Ok(generated),
                        Err(repair_error) => {
                            latest_raw = repair_raw;
                            latest_error = format!(
                                "{latest_error}; repair attempt {} failed: {}",
                                repair_attempt + 1,
                                repair_error.message
                            );
                        }
                    }
                }
            } else {
                for repair_attempt in
                    0..materialization_repair_pass_limit(request.renderer, repair_runtime_kind)
                {
                    let repair_payload =
                        build_studio_artifact_materialization_repair_prompt_for_runtime(
                            title,
                            intent,
                            request,
                            brief,
                            None,
                            None,
                            &[],
                            &[],
                            None,
                            refinement,
                            candidate_id,
                            candidate_seed,
                            &latest_raw,
                            &latest_error,
                            repair_runtime_kind,
                        )
                        .map_err(|message| {
                            StudioCandidateMaterializationError {
                                message,
                                raw_output_preview: truncate_candidate_failure_preview(
                                    &latest_raw,
                                    2000,
                                ),
                            }
                        })?;
                    let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                        StudioCandidateMaterializationError {
                            message: format!(
                                "Failed to encode Studio direct-author repair prompt: {}",
                                error
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                        }
                    })?;
                    let repair_output = repair_runtime
                        .execute_inference(
                            [0u8; 32],
                            &repair_input,
                            InferenceOptions {
                                temperature: 0.0,
                                json_mode: true,
                                max_tokens: materialization_max_tokens_for_execution_strategy(
                                    request.renderer,
                                    StudioExecutionStrategy::DirectAuthor,
                                    repair_runtime_kind,
                                ),
                                ..Default::default()
                            },
                        )
                        .await
                        .map_err(|error| StudioCandidateMaterializationError {
                            message: format!(
                                "{latest_error}; repair attempt {} inference failed: {error}",
                                repair_attempt + 1
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                        })?;
                    let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                        StudioCandidateMaterializationError {
                            message: format!(
                                "{latest_error}; repair attempt {} utf8 decode failed: {error}",
                                repair_attempt + 1
                            ),
                            raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
                        }
                    })?;
                    match parse_candidate(&repair_raw) {
                        Ok(generated) => return Ok(generated),
                        Err(repair_error) => {
                            latest_raw = repair_raw;
                            latest_error = format!(
                                "{latest_error}; repair attempt {} failed: {}",
                                repair_attempt + 1,
                                repair_error.message
                            );
                        }
                    }
                }
            }

            Err(StudioCandidateMaterializationError {
                message: latest_error,
                raw_output_preview: truncate_candidate_failure_preview(&latest_raw, 2000),
            })
        }
    }
}

pub async fn materialize_studio_artifact_candidate_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    temperature: f32,
) -> Result<StudioGeneratedArtifactPayload, String> {
    materialize_studio_artifact_candidate_with_runtime_detailed(
        runtime,
        None,
        title,
        intent,
        request,
        brief,
        None,
        None,
        &[],
        &[],
        edit_intent,
        refinement,
        candidate_id,
        candidate_seed,
        temperature,
    )
    .await
    .map_err(|error| error.message)
}

pub(crate) async fn refine_studio_artifact_candidate_with_runtime(
    runtime: Arc<dyn InferenceRuntime>,
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate: &StudioGeneratedArtifactPayload,
    judge: &StudioArtifactJudgeResult,
    candidate_id: &str,
    candidate_seed: u64,
    refinement_temperature: f32,
) -> Result<StudioGeneratedArtifactPayload, String> {
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    let parse_candidate = |raw: &str| -> Result<StudioGeneratedArtifactPayload, String> {
        let mut generated = super::parse_and_validate_generated_artifact_payload(raw, request)?;
        trace_html_contract_state(
            "artifact_generation:refine_contract_state:parsed",
            request,
            candidate_id,
            &generated,
        );
        super::enrich_generated_artifact_payload(&mut generated, request, brief);
        trace_html_contract_state(
            "artifact_generation:refine_contract_state:enriched",
            request,
            candidate_id,
            &generated,
        );
        super::validate_generated_artifact_payload_against_brief_with_edit_intent(
            &generated,
            request,
            brief,
            edit_intent,
        )?;
        Ok(generated)
    };
    let payload = build_studio_artifact_candidate_refinement_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        blueprint,
        artifact_ir,
        selected_skills,
        retrieved_exemplars,
        edit_intent,
        refinement,
        candidate,
        judge,
        candidate_id,
        candidate_seed,
        runtime_kind,
    )?;
    let input = serde_json::to_vec(&payload)
        .map_err(|error| format!("Failed to encode Studio artifact refinement prompt: {error}"))?;
    let runtime_kind = runtime.studio_runtime_provenance().kind;
    studio_generation_trace(format!(
        "artifact_generation:refine_inference:start id={} prompt_bytes={} temperature={} max_tokens={}",
        candidate_id,
        input.len(),
        refinement_temperature,
        materialization_max_tokens_for_runtime(request.renderer, runtime_kind)
    ));
    let output = runtime
        .execute_inference(
            [0u8; 32],
            &input,
            InferenceOptions {
                temperature: refinement_temperature,
                json_mode: true,
                max_tokens: materialization_max_tokens_for_runtime(request.renderer, runtime_kind),
                ..Default::default()
            },
        )
        .await
        .map_err(|error| format!("Studio artifact refinement inference failed: {error}"))?;
    studio_generation_trace(format!(
        "artifact_generation:refine_inference:ok id={} bytes={}",
        candidate_id,
        output.len()
    ));
    let raw = String::from_utf8(output)
        .map_err(|error| format!("Studio artifact refinement utf8 decode failed: {error}"))?;
    match parse_candidate(&raw) {
        Ok(generated) => Ok(generated),
        Err(first_error) => {
            studio_generation_trace(format!(
                "artifact_generation:refine_parse_error id={} error={} preview={}",
                candidate_id,
                first_error,
                truncate_candidate_failure_preview(&raw, 1200)
                    .unwrap_or_else(|| "(empty)".to_string())
            ));
            let mut latest_error = first_error;
            let mut latest_raw = raw;

            for repair_attempt in
                0..materialization_repair_pass_limit(request.renderer, runtime_kind)
            {
                let repair_payload =
                    build_studio_artifact_candidate_refinement_repair_prompt_for_runtime(
                        title,
                        intent,
                        request,
                        brief,
                        blueprint,
                        artifact_ir,
                        selected_skills,
                        retrieved_exemplars,
                        edit_intent,
                        refinement,
                        candidate,
                        judge,
                        candidate_id,
                        candidate_seed,
                        &latest_raw,
                        &latest_error,
                        runtime_kind,
                    )?;
                let repair_input = serde_json::to_vec(&repair_payload).map_err(|error| {
                    format!("Failed to encode Studio artifact refinement repair prompt: {error}")
                })?;
                studio_generation_trace(format!(
                    "artifact_generation:refine_repair:start id={} attempt={} prompt_bytes={}",
                    candidate_id,
                    repair_attempt + 1,
                    repair_input.len()
                ));
                let repair_output = runtime
                    .execute_inference(
                        [0u8; 32],
                        &repair_input,
                        InferenceOptions {
                            temperature: 0.0,
                            json_mode: true,
                            max_tokens: materialization_max_tokens_for_runtime(
                                request.renderer,
                                runtime_kind,
                            ),
                            ..Default::default()
                        },
                    )
                    .await
                    .map_err(|error| {
                        format!(
                            "{latest_error}; refinement repair attempt {} inference failed: {error}",
                            repair_attempt + 1
                        )
                    })?;
                studio_generation_trace(format!(
                    "artifact_generation:refine_repair:ok id={} attempt={} bytes={}",
                    candidate_id,
                    repair_attempt + 1,
                    repair_output.len()
                ));
                let repair_raw = String::from_utf8(repair_output).map_err(|error| {
                    format!(
                        "{latest_error}; refinement repair attempt {} utf8 decode failed: {error}",
                        repair_attempt + 1
                    )
                })?;
                match parse_candidate(&repair_raw) {
                    Ok(generated) => return Ok(generated),
                    Err(repair_error) => {
                        studio_generation_trace(format!(
                            "artifact_generation:refine_repair_parse_error id={} attempt={} error={} preview={}",
                            candidate_id,
                            repair_attempt + 1,
                            repair_error,
                            truncate_candidate_failure_preview(&repair_raw, 1200)
                                .unwrap_or_else(|| "(empty)".to_string())
                        ));
                        latest_raw = repair_raw;
                        latest_error = format!(
                            "{latest_error}; refinement repair attempt {} failed: {repair_error}",
                            repair_attempt + 1
                        );
                    }
                }
            }

            Err(latest_error)
        }
    }
}

pub(super) fn materialization_repair_pass_limit(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> usize {
    match renderer {
        StudioRendererKind::HtmlIframe
            if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime =>
        {
            1
        }
        StudioRendererKind::HtmlIframe => 3,
        StudioRendererKind::PdfEmbed => 3,
        _ => 1,
    }
}

pub fn build_studio_artifact_materialization_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
) -> Result<serde_json::Value, String> {
    build_studio_artifact_materialization_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        None,
        None,
        &[],
        &[],
        edit_intent,
        refinement,
        candidate_id,
        candidate_seed,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

pub(crate) fn build_studio_artifact_materialization_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_materialization_prompt(request.renderer, runtime_kind);
    let resolved_blueprint = blueprint
        .cloned()
        .unwrap_or_else(|| derive_studio_artifact_blueprint(request, brief));
    let resolved_artifact_ir = artifact_ir
        .cloned()
        .unwrap_or_else(|| compile_studio_artifact_ir(request, brief, &resolved_blueprint));
    let surface_contracts = studio_surface_contract_prompt_bundle(
        brief,
        &resolved_blueprint,
        &resolved_artifact_ir,
        selected_skills,
        candidate_seed,
    );
    let edit_intent_json = serialize_materialization_prompt_json(
        &edit_intent,
        "Studio artifact edit intent",
        compact_prompt,
    )?;
    let refinement_json = serialize_materialization_prompt_json(
        &studio_artifact_refinement_context_view(refinement),
        "Studio refinement context",
        compact_prompt,
    )?;
    let interaction_contract_json = serialize_materialization_prompt_json(
        &super::studio_artifact_interaction_contract(brief),
        "Studio interaction contract",
        compact_prompt,
    )?;
    let renderer_guidance = studio_artifact_renderer_authoring_guidance_for_runtime(
        request,
        brief,
        candidate_seed,
        runtime_kind,
    );
    let scaffold_execution_digest = surface_contracts.execution_digest.clone();
    let scaffold_execution_block = if scaffold_execution_digest.is_empty() {
        String::new()
    } else {
        format!(
            "\n\nScaffold execution digest:\n{}",
            if compact_prompt {
                truncate_materialization_focus_text(&scaffold_execution_digest, 280)
            } else {
                scaffold_execution_digest
            }
        )
    };
    let refinement_wrapper_directive = if refinement.is_some() {
        "\n\nRefinement output contract:\nReturn the patched artifact inside the exact JSON schema below; do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object."
    } else {
        ""
    };
    let schema_contract =
        studio_artifact_materialization_schema_contract_for_runtime(request.renderer, runtime_kind);
    if compact_prompt {
        let request_focus_text = compact_local_html_materialization_request_text(request);
        let brief_focus_text = compact_local_html_materialization_brief_text(brief);
        let interaction_contract_text = compact_local_html_interaction_contract_text(brief);
        let refinement_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_refinement_context_focus(refinement),
            "Studio refinement context",
            true,
        )?;

        return Ok(json!([
            {
                "role": "system",
                "content": "You are Studio's typed artifact materializer. Produce exactly one JSON object. The typed brief, edit intent, and current artifact context are authoritative. Do not emit prose outside JSON."
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus:\n{}\n\nArtifact brief focus:\n{}\n\nInteraction contract:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context JSON:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
                    title,
                    intent,
                    request_focus_text,
                    brief_focus_text,
                    interaction_contract_text,
                    edit_intent_json,
                    refinement_focus_json,
                    candidate_id,
                    candidate_seed,
                    refinement_wrapper_directive,
                    renderer_guidance,
                    schema_contract,
                )
            }
        ]));
    }

    let request_json =
        serialize_materialization_prompt_json(request, "Studio artifact request", compact_prompt)?;
    let brief_json =
        serialize_materialization_prompt_json(brief, "Studio artifact brief", compact_prompt)?;
    let blueprint_json = serialize_materialization_prompt_json(
        &resolved_blueprint,
        "Studio artifact blueprint",
        compact_prompt,
    )?;
    let artifact_ir_json = serialize_materialization_prompt_json(
        &resolved_artifact_ir,
        "Studio artifact IR",
        compact_prompt,
    )?;
    let selected_skills_json = serialize_materialization_prompt_json(
        &studio_artifact_selected_skill_prompt_view(selected_skills),
        "Studio selected skill guidance",
        compact_prompt,
    )?;
    let retrieved_exemplars_json = serialize_materialization_prompt_json(
        &studio_artifact_exemplar_prompt_view(retrieved_exemplars),
        "Studio retrieved exemplars",
        compact_prompt,
    )?;
    let promoted_design_spine_json = serialize_materialization_prompt_json(
        &surface_contracts.design_spine,
        surface_contracts.design_label,
        compact_prompt,
    )?;
    let scaffold_contract_json = serialize_materialization_prompt_json(
        &surface_contracts.scaffold_contract,
        surface_contracts.scaffold_label,
        compact_prompt,
    )?;
    let component_pack_contract_json = serialize_materialization_prompt_json(
        &surface_contracts.component_packs,
        surface_contracts.component_label,
        compact_prompt,
    )?;
    let design_label = format!("{} JSON", surface_contracts.design_label);
    let scaffold_label = format!("{} JSON", surface_contracts.scaffold_label);
    let component_label = format!("{} JSON", surface_contracts.component_label);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact materializer. Produce exactly one JSON object. The typed brief, edit intent, and current artifact context are authoritative. Do not emit prose outside JSON."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nArtifact brief JSON:\n{}\n\nArtifact blueprint JSON:\n{}\n\nArtifact IR JSON:\n{}\n\nSelected skill guidance JSON:\n{}\n\nRetrieved exemplar JSON:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n{}{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
                title,
                intent,
                request_json,
                brief_json,
                blueprint_json,
                artifact_ir_json,
                selected_skills_json,
                retrieved_exemplars_json,
                design_label,
                promoted_design_spine_json,
                scaffold_label,
                scaffold_contract_json,
                component_label,
                component_pack_contract_json,
                interaction_contract_json,
                edit_intent_json,
                refinement_json,
                candidate_id,
                candidate_seed,
                refinement_wrapper_directive,
                scaffold_execution_block,
                renderer_guidance,
                schema_contract,
            )
        }
    ]))
}

pub(crate) fn build_studio_artifact_direct_author_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    runtime_kind: StudioRuntimeProvenanceKind,
    returns_raw_document: bool,
) -> Result<serde_json::Value, String> {
    let renderer_guidance =
        studio_direct_author_renderer_guidance(request, candidate_seed, runtime_kind);
    let compact_local_renderer_guidance = if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == StudioRendererKind::HtmlIframe
        && returns_raw_document
    {
        "Keep the page compact and finishable in one local-model pass.\n- Use one self-contained index.html with concise inline CSS and tiny inline JavaScript.\n- Prefer 2-4 meaningful sections and one strong interactive seam instead of a dashboard shell or long style system.\n- Keep visible markup first, keep CSS lean, avoid decorative comment blocks, and do not spend the response on exhaustive theming.\n- Use semantic HTML with <main>, ship a complete default state on first paint, and end with a fully closed </body></html>."
            .to_string()
    } else {
        renderer_guidance.clone()
    };
    let output_contract = if returns_raw_document {
        match request.renderer {
            StudioRendererKind::Markdown => {
                "Output contract:\n- Return only one complete markdown document.\n- Do not wrap the document in JSON.\n- Do not wrap the document in markdown fences.\n- Keep the document request-specific and complete on first pass."
            }
            StudioRendererKind::HtmlIframe => {
                "Output contract:\n- Return only one complete self-contained HTML document.\n- Start with <!doctype html> or <html> and end with </html>.\n- Do not wrap the document in JSON.\n- Do not wrap the document in markdown fences.\n- Keep the authored file request-specific, complete on first paint, and ready to save as index.html."
            }
            StudioRendererKind::Svg => {
                "Output contract:\n- Return only one complete standalone SVG document.\n- Start with <svg and end with </svg>.\n- Do not wrap the SVG in JSON or markdown fences.\n- Keep the artifact request-specific and complete on first pass."
            }
            StudioRendererKind::Mermaid => {
                "Output contract:\n- Return only Mermaid diagram source.\n- Do not wrap the diagram in JSON or markdown fences.\n- Keep the diagram request-specific and complete on first pass."
            }
            StudioRendererKind::PdfEmbed => {
                "Output contract:\n- Return only the complete document text that should be compiled into the PDF artifact.\n- Do not return binary data, LaTeX, JSON, or markdown fences.\n- Keep the document request-specific and complete on first pass."
            }
            _ => {
                "Output contract:\n- Return only the complete authored document.\n- Do not wrap it in JSON or markdown fences."
            }
        }
    } else {
        studio_artifact_materialization_schema_contract_for_runtime(request.renderer, runtime_kind)
    };
    let direct_author_contract = if returns_raw_document {
        "Direct authoring contract:\n- Preserve the raw user request as the primary instruction.\n- Author the requested single-document artifact directly instead of inventing a generic platform artifact.\n- Produce one complete, request-specific document for the typed renderer.\n- Do not introduce planner summaries, blueprint language, or generalized artifact boilerplate into visible copy unless the request asked for it."
    } else {
        "Direct authoring contract:\n- Preserve the raw user request as the primary instruction.\n- Author the requested artifact directly instead of inventing a generic platform artifact.\n- Return exactly one JSON object in the schema below.\n- Do not introduce planner summaries, blueprint language, or generalized artifact boilerplate into visible copy unless the request asked for it."
    };
    let system_contract = if returns_raw_document {
        if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
            "You are Studio's direct document author. The raw user request is the primary instruction. Return only the completed document body for the requested renderer. Do not emit JSON, summaries, notes, keys, prose, or markdown fences before the document. If the renderer is html_iframe, the very first non-whitespace characters must be <!doctype html> or <html>."
        } else {
            "You are Studio's direct document author. The raw user request is the primary instruction. Author the artifact directly and return only the completed document body for the requested renderer. Do not emit prose, markdown fences, or JSON."
        }
    } else {
        "You are Studio's typed artifact materializer. The raw user request is the primary instruction. Author the artifact directly and return exactly one JSON object. Do not emit prose outside JSON."
    };

    if compact_local_direct_author_prompt(runtime_kind, returns_raw_document) {
        if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
            && request.renderer == StudioRendererKind::HtmlIframe
            && returns_raw_document
        {
            return Ok(json!([
                {
                    "role": "system",
                    "content": "Return only one complete self-contained index.html. Start with <!doctype html> and end with </html>. Do not emit JSON, markdown fences, notes, or explanation. Keep inline CSS concise, keep inline JavaScript tiny, and spend the response on the actual document rather than wrapper boilerplate."
                },
                {
                    "role": "user",
                    "content": format!(
                        "{}\n\nRequirements:\n- Deliver one request-specific interactive HTML document.\n- Use semantic HTML with <main> and 2-4 meaningful sections.\n- Keep first paint useful before scripts run.\n- Include one real interactive seam that changes visible evidence or explanatory copy.\n- Keep CSS short enough to finish the full document in one pass.\n- End with a fully closed </main></body></html>.",
                        intent.trim()
                    )
                }
            ]));
        }

        let mut sections = vec![
            Some(format!("Title: {}", title.trim())),
            Some(format!("Raw user request:\n{}", intent.trim())),
            refinement.map(|context| {
                format!(
                    "Existing artifact context:\n{}",
                    truncate_materialization_focus_text(&context.summary, 180)
                )
            }),
            Some(direct_author_contract.to_string()),
            Some(format!(
                "Renderer-native authoring guidance:\n{}",
                compact_local_renderer_guidance
            )),
            Some(output_contract.to_string()),
            if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
                && request.renderer == StudioRendererKind::HtmlIframe
            {
                Some(
                    "Return format hard requirement:\n- Start immediately with <!doctype html>.\n- Do not output JSON keys like summary, notes, or files.\n- Spend the response budget on the actual document body, not wrapper metadata."
                        .to_string(),
                )
            } else {
                None
            },
        ];
        sections.retain(|entry| entry.as_ref().is_some_and(|text| !text.trim().is_empty()));

        return Ok(json!([
            {
                "role": "system",
                "content": system_contract
            },
            {
                "role": "user",
                "content": sections
                    .into_iter()
                    .flatten()
                    .collect::<Vec<_>>()
                    .join("\n\n")
            }
        ]));
    }

    let compact_prompt = compact_local_html_materialization_prompt(request.renderer, runtime_kind);
    let request_focus_json = serialize_materialization_prompt_json(
        &compact_local_html_materialization_request_focus(request),
        "Studio artifact request focus",
        compact_prompt,
    )?;
    let refinement_json = serialize_materialization_prompt_json(
        &studio_artifact_refinement_context_view(refinement),
        "Studio refinement context",
        compact_prompt,
    )?;

    Ok(json!([
        {
            "role": "system",
            "content": system_contract
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRaw user request:\n{}\n\nArtifact request focus JSON:\n{}\n\nCurrent artifact context JSON:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
                title,
                intent,
                request_focus_json,
                refinement_json,
                candidate_id,
                candidate_seed,
                direct_author_contract,
                renderer_guidance,
                output_contract,
            )
        }
    ]))
}

fn build_studio_artifact_direct_author_continuation_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    partial_document: &str,
    latest_error: &str,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> serde_json::Value {
    let boundary = direct_author_completion_boundary(request).unwrap_or("</html>");
    let continuation_contract = match request.renderer {
        StudioRendererKind::HtmlIframe => {
            "Return only the missing HTML suffix. Do not restart from <!doctype html>, <html>, <head>, or <body>. Continue exactly where the partial document stopped and make sure the final combined document ends with </body></html>."
        }
        StudioRendererKind::Svg => {
            "Return only the missing SVG suffix. Do not restart from <svg>. Continue exactly where the partial document stopped and make sure the final combined document ends with </svg>."
        }
        _ => {
            "Return only the missing document suffix. Do not repeat the earlier portion."
        }
    };
    let tail = live_token_stream_preview_text(partial_document, 4000);
    let system_contract = if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
        "You are Studio's direct document author continuing an interrupted document. Return only the missing suffix. Do not emit JSON, summaries, markdown fences, or explanations."
    } else {
        "You are Studio's direct document author. Continue the interrupted document by returning only the missing suffix."
    };
    json!([
        {
            "role": "system",
            "content": system_contract
        },
        {
            "role": "user",
            "content": format!(
                "Title: {}\n\nRaw user request:\n{}\n\nValidation failure:\n{}\n\nContinuation contract:\n{}\n\nThe current partial document is below. Continue from the exact stopping point, do not repeat earlier content, and end the combined document with {}.\n\nPartial document tail:\n{}",
                title.trim(),
                intent.trim(),
                latest_error.trim(),
                continuation_contract,
                boundary,
                tail,
            )
        }
    ])
}

fn build_studio_artifact_direct_author_repair_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    invalid_document: &str,
    latest_error: &str,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> serde_json::Value {
    let renderer_guidance =
        studio_direct_author_renderer_guidance(request, candidate_seed_for(title, intent, 0), runtime_kind);
    let output_contract = match request.renderer {
        StudioRendererKind::Markdown => {
            "Return one complete corrected markdown document only."
        }
        StudioRendererKind::HtmlIframe => {
            "Return one complete corrected self-contained HTML document only. Start with <!doctype html> or <html> and end with </html>."
        }
        StudioRendererKind::Svg => {
            "Return one complete corrected standalone SVG document only. Start with <svg and end with </svg>."
        }
        StudioRendererKind::Mermaid => {
            "Return one complete corrected Mermaid document only."
        }
        StudioRendererKind::PdfEmbed => {
            "Return one complete corrected document text only."
        }
        _ => "Return one complete corrected document only.",
    };
    let system_contract = if runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime {
        "You are Studio's direct document repair author. Return only the corrected document. Do not emit JSON, summaries, notes, or markdown fences."
    } else {
        "You are Studio's direct document repair author. Return only the corrected document."
    };
    json!([
        {
            "role": "system",
            "content": system_contract
        },
        {
            "role": "user",
            "content": format!(
                "Title: {}\n\nRaw user request:\n{}\n\nValidation failure:\n{}\n\nRepair contract:\n- Preserve the existing authored direction when possible.\n- Correct the structural failure without switching to a generic platform artifact.\n- {}\n\nRenderer-native guidance:\n{}\n\nCurrent invalid document:\n{}",
                title.trim(),
                intent.trim(),
                latest_error.trim(),
                output_contract,
                renderer_guidance,
                invalid_document,
            )
        }
    ])
}

fn studio_artifact_materialization_schema_contract() -> &'static str {
    "Return exactly one JSON object with this camelCase schema:\n{\n  \"summary\": <string>,\n  \"notes\": [<string>],\n  \"files\": [\n    {\n      \"path\": <string>,\n      \"mime\": <string>,\n      \"role\": \"primary\" | \"source\" | \"export\" | \"supporting\",\n      \"renderable\": <boolean>,\n      \"downloadable\": <boolean>,\n      \"encoding\": null | \"utf8\" | \"base64\",\n      \"body\": <string>\n    }\n  ]\n}\nRules:\n1) Respect the typed renderer exactly.\n2) markdown => one renderable .md file.\n3) html_iframe => one renderable .html file with inline CSS/JS only.\n4) html_iframe must use semantic HTML structure: include <main> plus at least three sectioning elements drawn from <section>, <article>, <nav>, <aside>, or <footer>.\n5) html_iframe must ground requiredInteractions in real controls or interactive regions, not just static headings.\n6) html_iframe must realize required interactions as on-page state changes, revealed detail, filtering, comparison, tutorial stepping, or comparable DOM behavior.\n7) html_iframe must ship interactive regions with actual first-paint content and data; empty containers, comment-only handlers, or explanation-only scripts do not count as implementation.\n8) html_iframe must include a first-paint control set plus a shared detail, comparison, or explanation region when requiredInteractions are non-empty.\n9) html_iframe view-switching or navigation interactions must change inline content or shared detail state; anchor-only jump links do not count as sufficient implementation.\n10) html_iframe must render the default selected chart, label, and detail state directly in the markup before any script runs; scripts may enhance or switch it, but must not create the only visible first-paint content from empty shells.\n11) html_iframe must not use alert(), dead buttons, submit-to-nowhere forms, or navigation-only controls as the main interaction.\n12) html_iframe must not invent custom element tags like <toolbox> or <demo>; use standard HTML elements, classes, and data-* attributes.\n13) html_iframe must not depend on external libraries, undefined globals, or remote placeholder media; render charts and diagrams with inline SVG, canvas, or DOM/CSS.\n14) html_iframe must prefer inline SVG or DOM data marks over blank canvas shells; a canvas-only placeholder does not count as first-paint implementation.\n15) html_iframe chart or diagram regions rendered with SVG must contain real marks plus visible labels, legend text, or accessible labels on first paint; abstract geometry alone does not count.\n16) html_iframe chart or diagram controls should update a shared detail, comparison, or explanation region instead of acting as decorative navigation.\n17) html_iframe must not include HTML comments, placeholder comments, TODO markers, or script references to DOM ids that do not exist in the document.\n18) html_iframe must not emit the literal words placeholder, placeholders, TODO, or TBD anywhere in the final HTML, CSS, JavaScript, comments, ids, classes, or visible copy.\n19) jsx_sandbox => one renderable .jsx file with a default export.\n20) svg => one renderable .svg file.\n21) mermaid => one renderable .mermaid file.\n22) pdf_embed => one .pdf file whose body is the document text that Studio will compile into PDF bytes, and the document text must still be returned inside this JSON object as files[0].body rather than as raw prose outside JSON.\n23) download_card => downloadable export files only; do not mark them renderable.\n24) bundle_manifest => a .json manifest plus any supporting files required by the bundle.\n25) workspace_surface must not be used here.\n26) The visible composition must surface the differentiating request concepts from artifactThesis and requiredConcepts, not just the broad category.\n27) Do not use placeholder image URLs, placeholder copy, generic stock filler, or fake media placeholders. Prefer typographic, diagrammatic, or CSS-native composition over fake media placeholders.\n28) If the artifact could fit many unrelated prompts by only swapping the heading, it is not acceptable.\n29) Honor refinement continuity when editIntent.mode is patch or branch.\n30) Prefer truthful partial output over invented completion.\n31) html_iframe controls that iterate across multiple buttons, cards, or marks must target collections correctly; use querySelectorAll or an equivalent collection before calling forEach or similar methods, and keep every referenced view present in the markup.\n32) html_iframe clickable navigation should use explicit static control-to-panel mappings such as data-view plus data-view-panel, aria-controls, or data-target tied to pre-rendered views. Use the literal data-view-panel attribute on the panel element itself; a CSS class like class=\"data-view-panel\" does not satisfy this contract. Do not synthesize target ids by concatenating button ids or other runtime strings.\n33) html_iframe briefs that call for charts, diagrams, metrics, or comparisons must surface at least two distinct first-paint evidence views or chart families tied to different requiredConcepts or referenceHints; one chart plus generic prose is insufficient, and blank mount divs like <div id=\"usage-chart\"></div> do not count as evidence views.\n34) html_iframe briefs that require both clickable view switching and rollover detail must satisfy both in the same document: keep at least two pre-rendered panels plus visible data-detail marks that update one shared detail region on click and hover/focus. Do not repair one interaction by deleting the other.\n35) html_iframe marks that rely on focus handlers must be focusable, such as via tabindex=\"0\" or naturally focusable elements.\n36) html_iframe view-switching briefs must not point multiple controls only at one shared detail region; each switchable control needs its own pre-rendered panel container. If you emit controls like data-view=\"overview\", data-view=\"comparison\", and data-view=\"details\", emit matching containers like <section data-view-panel=\"overview\">...</section>, <section data-view-panel=\"comparison\" hidden>...</section>, and <section data-view-panel=\"details\" hidden>...</section>, keep the literal data-view-panel attribute on those panel elements, and then toggle them through a panels collection like querySelectorAll('[data-view-panel]').\n37) Keep visible markup first: place the script tag after the closing </main> or at the end of <body>, not as a long head script before the surfaced sections.\n38) Prefer dataset comparisons such as panel.dataset.viewPanel !== button.dataset.view instead of building a querySelector string with nested quoted fragments.\n39) Static data-view, aria-controls, or data-target attributes do not satisfy clickable navigation by themselves; wire click or change handlers that toggle hidden, aria-selected, aria-hidden, data-active, or comparable state on the mapped panel wrappers.\n40) Class names like class=\"overview-panel\" or class=\"data-view-panel\" do not establish a mapped panel; put the mapping on the wrapper itself with literal attributes such as id=\"overview-panel\" and data-view-panel=\"overview\".\n41) Apply sequence-browsing requirements only when interactionContract.sequenceBrowsingRequired is true. In that case, expose a visible progression control on first paint such as a stepper, previous/next controls, a scrubber, or a scroll-snap evidence rail. A static chart plus unrelated panel toggles does not satisfy sequence browsing."
}

fn studio_artifact_materialization_schema_contract_for_runtime(
    renderer: StudioRendererKind,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> &'static str {
    if renderer == StudioRendererKind::HtmlIframe && studio_modal_first_html_enabled() {
        return "Return exactly one JSON object with this camelCase schema:\n{\n  \"summary\": <string>,\n  \"notes\": [<string>],\n  \"files\": [\n    {\n      \"path\": <string>,\n      \"mime\": <string>,\n      \"role\": \"primary\" | \"source\" | \"export\" | \"supporting\",\n      \"renderable\": <boolean>,\n      \"downloadable\": <boolean>,\n      \"encoding\": null | \"utf8\" | \"base64\",\n      \"body\": <string>\n    }\n  ]\n}\nRules:\n1) Respect the typed renderer exactly.\n2) html_iframe => one self-contained renderable .html file with inline CSS/JS only.\n3) Use standard HTML with <body><main>...</main></body> and meaningful surfaced content.\n4) First paint must already show a complete default state for the chosen interaction grammar.\n5) Choose the interaction model that best fits the request: tabs, toggles, inspectable marks, steppers, scrubbers, sceneboards, inline simulators, annotated diagrams, or another truthful inline state-change pattern.\n6) If view switching is required, switch between authored on-page states, scenes, or sections with a visible state change; mapped panels are allowed but not mandatory.\n7) If detail inspection is required, reveal deeper context inline through captions, annotations, callouts, overlays, drawers, or contextual text; no fixed shared detail panel is required.\n8) If sequence browsing is required, expose a visible progression control on first paint such as previous/next, a stepper, a scrubber, or an evidence rail.\n9) Keep visible content in the raw HTML before scripts run; scripts may change authored state but must not create the only meaningful first-paint content from nothing.\n10) Use inline SVG, canvas, or DOM/CSS with visible labels when the brief calls for diagrams, metrics, or visual evidence.\n11) Interactive explainers must connect at least two meaningful request-grounded state changes; one isolated button, lone slider, or decorative toggle is insufficient.\n12) Controls only count when they update labeled evidence, simulation state, comparison state, or explanatory copy tied to the request concepts.\n13) Establish an intentional visual system with purposeful typography, spacing, contrast, and palette; default browser-body styling or plain white document layouts are not acceptable unless the request explicitly calls for them.\n14) Do not use alert(), dead buttons, submit-nowhere forms, navigation-only controls, placeholder copy, TODO markers, HTML comments, nonexistent DOM ids, or external libraries.\n15) Keep the artifact request-specific, refinement-faithful, and truthful rather than inventing completion.";
    }
    if compact_local_html_materialization_prompt(renderer, runtime_kind) {
        if studio_modal_first_html_enabled() {
            return "Return exactly one JSON object with this camelCase schema:\n{\n  \"summary\": <string>,\n  \"notes\": [<string>],\n  \"files\": [\n    {\n      \"path\": <string>,\n      \"mime\": <string>,\n      \"role\": \"primary\" | \"source\" | \"export\" | \"supporting\",\n      \"renderable\": <boolean>,\n      \"downloadable\": <boolean>,\n      \"encoding\": null | \"utf8\" | \"base64\",\n      \"body\": <string>\n    }\n  ]\n}\nRules:\n1) Respect the typed renderer exactly.\n2) html_iframe => one self-contained renderable .html file with inline CSS/JS only.\n3) Use standard HTML with <body><main>...</main></body> and meaningful surfaced content.\n4) First paint must already show a complete default state for the chosen interaction grammar.\n5) Choose the interaction model that best fits the request: tabs, toggles, inspectable marks, steppers, scrubbers, sceneboards, inline simulators, annotated diagrams, or another truthful inline state-change pattern.\n6) If view switching is required, switch between authored on-page states, scenes, or sections with a visible state change; mapped panels are allowed but not mandatory.\n7) If detail inspection is required, reveal deeper context inline through captions, annotations, callouts, overlays, drawers, or contextual text; no fixed shared detail panel is required.\n8) If sequence browsing is required, expose a visible progression control on first paint such as previous/next, a stepper, a scrubber, or an evidence rail.\n9) Keep visible content in the raw HTML before scripts run; scripts may change authored state but must not create the only meaningful first-paint content from nothing.\n10) Use inline SVG, canvas, or DOM/CSS with visible labels when the brief calls for diagrams, metrics, or visual evidence.\n11) Interactive explainers must connect at least two meaningful request-grounded state changes; one isolated button, lone slider, or decorative toggle is insufficient.\n12) Controls only count when they update labeled evidence, simulation state, comparison state, or explanatory copy tied to the request concepts.\n13) Establish an intentional visual system with purposeful typography, spacing, contrast, and palette; default browser-body styling or plain white document layouts are not acceptable unless the request explicitly calls for them.\n14) Do not use alert(), dead buttons, submit-nowhere forms, navigation-only controls, placeholder copy, TODO markers, HTML comments, nonexistent DOM ids, or external libraries.\n15) Keep the artifact request-specific, refinement-faithful, and truthful rather than inventing completion.";
        }
        return "Return exactly one JSON object with this camelCase schema:\n{\n  \"summary\": <string>,\n  \"notes\": [<string>],\n  \"files\": [\n    {\n      \"path\": <string>,\n      \"mime\": <string>,\n      \"role\": \"primary\" | \"source\" | \"export\" | \"supporting\",\n      \"renderable\": <boolean>,\n      \"downloadable\": <boolean>,\n      \"encoding\": null | \"utf8\" | \"base64\",\n      \"body\": <string>\n    }\n  ]\n}\nRules:\n1) Respect the typed renderer exactly.\n2) html_iframe => one self-contained renderable .html file with inline CSS/JS only.\n3) Use standard HTML with <body><main>...</main></body> and at least three sectioning elements inside <main>.\n4) Start the visible composition immediately inside <main>; do not spend most of the response budget on a long style block before the first surfaced section.\n5) First paint must already show a real control set, two populated evidence surfaces, and one shared detail or comparison region.\n6) If the artifact uses buttons, tabs, or chips to switch views, emit at least two pre-rendered mapped panel containers in the raw HTML with literal attributes such as <button data-view=\"overview\" aria-controls=\"overview-panel\"> plus <section id=\"overview-panel\" data-view-panel=\"overview\">...</section> and a second hidden mapped panel.\n7) View-switching controls must toggle those pre-rendered mapped panels through literal attributes such as data-view plus data-view-panel or aria-controls; do not synthesize target ids at runtime, and do not point every control only at one shared detail region.\n8) If rollover detail is required, include visible [data-detail] marks that update the shared detail region on hover/focus, and make every such mark keyboard-focusable with tabindex=\"0\" or a naturally focusable element.\n9) If you include a shared detail, comparison, or explanation region, populate its default state directly in the HTML before any script runs; do not leave it empty on first paint.\n10) Render the default selected view and evidence directly in the HTML before any script runs, with exactly one mapped panel visible when view switching is present.\n11) Keep CSS concise and utility-first so the document can reach a complete closing </main></body></html> within the response budget.\n12) Use inline SVG or DOM/CSS evidence with visible labels; no blank shells, placeholders, HTML comments, TODOs, nonexistent ids, or external libraries.\n13) Do not emit the literal words placeholder, placeholders, TODO, or TBD anywhere in the final HTML, CSS, JavaScript, comments, ids, classes, or visible copy.\n14) Keep the artifact request-specific, refinement-faithful, and truthful rather than inventing completion.";
    }
    studio_artifact_materialization_schema_contract()
}

fn studio_artifact_renderer_authoring_guidance_for_runtime(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    candidate_seed: u64,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> String {
    if request.renderer == StudioRendererKind::HtmlIframe && studio_modal_first_html_enabled() {
        return studio_artifact_renderer_authoring_guidance(request, brief, candidate_seed);
    }
    if compact_local_html_materialization_prompt(request.renderer, runtime_kind) {
        if studio_modal_first_html_enabled() {
            let layout_recipe = match candidate_seed % 3 {
                0 => {
                    "editorial explainer with layered annotations and one decisive interactive seam"
                }
                1 => "scenario-driven workspace with an inline simulator or sceneboard",
                _ => "graphic narrative with inspectable marks and progression cues",
            };
            let concept_focus = summarized_guidance_terms(
                &brief.required_concepts,
                "the typed request concepts",
                4,
            );
            let interaction_focus = summarized_guidance_terms(
                &brief.required_interactions,
                "the required interactions",
                3,
            );
            let sequence_browsing_directive = if super::brief_requires_sequence_browsing(brief) {
                " Include a visible progression mechanic such as previous/next, a stepper, a scrubber, or an evidence rail."
            } else {
                ""
            };
            let view_switching_directive = if super::brief_requires_view_switching(brief) {
                " If view switching is part of the brief, switch between authored scenes, states, or sections with a visible on-page change; mapped panels are one valid pattern, not a requirement."
            } else {
                ""
            };
            let rollover_directive = if super::brief_requires_rollover_detail(brief) {
                " If detail inspection is part of the brief, let marks, cards, or inline callouts reveal deeper context without forcing a detached detail aside."
            } else {
                ""
            };
            return format!(
                "- Use the candidate seed to vary this composition recipe: {layout_recipe}.\n- Keep the artifact visibly grounded in these request concepts: {concept_focus}.\n- Make these interaction families tangible on first paint: {interaction_focus}.{sequence_browsing_directive}{view_switching_directive}{rollover_directive}\n- Ship one self-contained .html file with inline CSS/JS, <main>, and meaningful surfaced structure.\n- Open the document body with <main> immediately after <body>, and keep every visible artifact region inside that <main>.\n- First paint should already feel complete and useful, with at least two request-grounded zones of information density.\n- Choose the interaction grammar that best fits the request instead of defaulting to the same layout every time: sceneboard, stepper, scrubber, inspectable diagram, inline simulator, tabset, comparison story, or another truthful pattern are all valid.\n- Do not default to a left sidebar, dashboard shell, or app-style chrome unless the brief explicitly needs navigation.\n- For educational or explanatory briefs, prefer a living model, scenario walkthrough, inspectable diagram, or guided comparison over stacked textbook sections with decorative blocks.\n- Avoid the default classroom explainer pattern of stacked concept cards, repeated paragraph-plus-empty-box sections, or one interchangeable box per concept.\n- If the request is educational, still give it one strong visual metaphor or working interaction seam that makes the page feel authored rather than generic.\n- Make at least two interactions work together so user input changes both evidence and explanation; one isolated button or slider does not satisfy an interactive artifact.\n- Establish a clear visual system with purposeful typography, spacing, contrast, and palette; avoid default browser-white document styling unless the brief explicitly calls for a print-like minimal surface.\n- Render the default state directly in the HTML; scripts may switch, annotate, or simulate authored state but must not create the only meaningful first-paint content from empty shells.\n- Use inline SVG, canvas, or DOM/CSS evidence with visible labels when the brief calls for diagrams, metrics, or comparisons.\n- Keep CSS concise so the response reaches a complete closing </main></body></html> instead of collapsing inside styles.\n- Avoid ornamental scaffolding, decorative gradients, and repeated chrome when they do not help the explanation.\n- Do not emit the literal words placeholder, placeholders, TODO, or TBD anywhere in the final HTML, CSS, JavaScript, comments, ids, classes, or visible copy.\n- No jump-link-only navigation, placeholder media, HTML comments, nonexistent ids, or external libraries.",
            );
        }
        let layout_recipe = match candidate_seed % 3 {
            0 => "story-led hero with a control rail and detail aside",
            1 => "dashboard-led metrics rail with mapped evidence panels",
            _ => "editorial explainer with a stepper-style control row",
        };
        let concept_focus =
            summarized_guidance_terms(&brief.required_concepts, "the typed request concepts", 4);
        let interaction_focus =
            summarized_guidance_terms(&brief.required_interactions, "the required interactions", 3);
        let exact_view_scaffold = super::html_prompt_exact_view_scaffold(brief);
        let two_view_example = super::html_prompt_two_view_example(brief);
        let sequence_browsing_directive = if super::brief_requires_sequence_browsing(brief) {
            " Include a visible previous/next control, stepper, scrubber, or evidence rail for sequence browsing."
        } else {
            ""
        };
        let view_switching_directive = if super::brief_requires_view_switching(brief) {
            format!(
                " If view switching is part of the brief, follow a mapped-panel scaffold such as {}. Pair it with a panels collection like querySelectorAll('[data-view-panel]') and toggle hidden plus aria-selected state on click instead of routing every control only to the shared detail region. A safe visible pairing is {} plus one populated <aside><p id=\"detail-copy\">...</p></aside>.",
                exact_view_scaffold,
                two_view_example
            )
        } else {
            String::new()
        };
        let rollover_directive = if super::brief_requires_rollover_detail(brief) {
            " Use focusable visible [data-detail] marks that update the shared detail panel on hover and focus."
        } else {
            ""
        };
        return format!(
            "- Use the candidate seed to vary this layout recipe: {layout_recipe}.\n- Keep the artifact visibly grounded in these request concepts: {concept_focus}.\n- Make these interaction families tangible on first paint: {interaction_focus}.{sequence_browsing_directive}{view_switching_directive}\n- Ship one self-contained .html file with inline CSS/JS, <main>, and at least three sectioning elements.\n- Open the document body with <main> immediately after <body>, and keep every visible artifact region inside that <main>.\n- Start from a safe minimal scaffold such as <!doctype html><html lang=\"en\"><head><meta charset=\"UTF-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1.0\"><title>...</title><style>body{{margin:0;font-family:system-ui,sans-serif;background:#0f172a;color:#e5e7eb}}main{{max-width:960px;margin:0 auto;padding:24px}}</style></head><body><main><section>...</section><section>...</section><aside>...</aside></main><script>...</script></body></html>.\n- First paint must include a request-specific hero, a real control bar, two populated evidence surfaces, and one shared detail or comparison aside.\n- Any shared detail, comparison, or explanation region must contain request-grounded default content in the raw HTML before script runs; do not leave it empty until interaction.\n- Keep exactly one mapped panel visible in the raw HTML before script runs; controls should toggle pre-rendered panels or rewrite the shared detail region.\n- Render the default selected view and evidence directly in the HTML; scripts may switch or annotate existing content but must not create the only first-paint content.\n- Use inline SVG or DOM/CSS evidence with visible labels and multiple marks, rows, or items per evidence surface.\n- Keep CSS concise and layout-led so the response reaches a complete closing </main></body></html> instead of ending inside styles.\n- Avoid long decorative token lists, animation scaffolds, or gradient-heavy style systems unless they are essential to the request.\n- Every visible [data-detail] mark should be keyboard-focusable through tabindex=\"0\" or a naturally focusable element such as a button.\n- Do not emit the literal words placeholder, placeholders, TODO, or TBD anywhere in the final HTML, CSS, JavaScript, comments, ids, classes, or visible copy.\n- No jump-link navigation, placeholder media, HTML comments, TODOs, nonexistent ids, or external libraries.{rollover_directive}",
        );
    }

    studio_artifact_renderer_authoring_guidance(request, brief, candidate_seed)
}

fn studio_artifact_renderer_authoring_guidance(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    candidate_seed: u64,
) -> String {
    match request.renderer {
        StudioRendererKind::HtmlIframe => {
            if studio_modal_first_html_enabled() {
                let layout_recipe = match candidate_seed % 3 {
                    0 => {
                        "editorial explainer with layered annotations, one active seam, and a compact evidence rhythm"
                    }
                    1 => {
                        "scenario-driven workspace with a visible simulator state and grounded comparison surfaces"
                    }
                    _ => {
                        "graphic narrative with inspectable marks, progression cues, and restrained utility chrome"
                    }
                };
                let concept_focus = summarized_guidance_terms(
                    &brief.required_concepts,
                    "the typed request concepts",
                    4,
                );
                let interaction_focus = summarized_guidance_terms(
                    &brief.required_interactions,
                    "the required interactions",
                    3,
                );
                let section_blueprint = html_first_paint_section_blueprint(brief);
                let evidence_plan = html_candidate_evidence_plan(brief, candidate_seed);
                let anchor_surface_directive = html_factual_anchor_surface_directive(brief);
                let interaction_distribution_directive =
                    html_interaction_distribution_directive(brief);
                let sequence_browsing_directive = if super::brief_requires_sequence_browsing(brief) {
                    "\n- When the brief implies progression, expose a visible progression control on first paint such as previous/next, a stepper, a scrubber, or an evidence rail."
                        .to_string()
                } else {
                    String::new()
                };
                let rollover_directive = if super::brief_requires_rollover_detail(brief) {
                    "\n- When the brief calls for inspection or hover detail, reveal deeper context inline through annotations, captions, callouts, overlays, drawers, or contextual text. Do not force a detached shared-detail aside unless it genuinely serves the artifact."
                        .to_string()
                } else {
                    String::new()
                };
                let view_switching_directive = if super::brief_requires_view_switching(brief) {
                    "\n- When the brief calls for switching views, move between authored scenes, states, or sections with a visible on-page change. Mapped panels are allowed but not required."
                        .to_string()
                } else {
                    String::new()
                };
                return format!(
                    "- Use the candidate seed to vary composition. This candidate should follow the layout recipe: {layout_recipe}.\n- Build the first paint around this section blueprint: {section_blueprint}.\n{evidence_plan}\n{anchor_surface_directive}\n{interaction_distribution_directive}\n- Derive visible controls, marks, and response regions from these brief concepts: {concept_focus}.\n- Make these required interactions tangible on first paint: {interaction_focus}.\n- Choose the interaction model that best serves the request instead of defaulting to one scaffold: tabs, steppers, sceneboards, inline simulators, inspectable diagrams, annotated cards, timelines, and comparison stories are all valid when they produce a truthful visible state change.\n- Do not default to a left navigation rail, dashboard frame, or generic application shell unless the request explicitly asks for one.\n- For educational or explanatory briefs, prefer a living model, scenario walkthrough, inspectable diagram, or guided comparison over stacked textbook sections with decorative blocks.\n- Keep the hero and primary heading request-specific; synthesize the thesis in your own words instead of pasting artifactThesis verbatim as the headline.\n- Surface every requiredConcept in visible headings, labels, legends, captions, callouts, or evidence notes, not only in the title.\n- Make each sectioning region independently meaningful on first paint: every <section>, <article>, <aside>, or <footer> should contain request-grounded content rather than acting as an empty future mount.\n- Ship interactive regions with actual first-paint content and data. Empty containers or comment-only handlers are not acceptable.\n- Make at least two interactions work together so user input changes both evidence and explanation; one isolated button or slider does not satisfy an interactive artifact.\n- Establish a clear visual system with purposeful typography, spacing, contrast, and palette; avoid default browser-white document styling unless the brief explicitly calls for a print-like minimal surface.\n- Render the default state directly in the HTML markup before the script tag. JavaScript should switch, annotate, scrub, or simulate authored state, not create the only meaningful first-paint content from nothing.\n- Keep visible markup first: place the script after the closing </main> or at the end of <body>, not as a long head script before the surfaced sections.\n- Build charts, diagrams, or explainers with inline SVG, canvas, or DOM/CSS. Do not rely on external libraries, undefined globals, or remote placeholder media.\n- Every chart or diagram must include visible labels, legend text, or accessible labels on first paint. Decorative geometry alone is not enough.{sequence_browsing_directive}{rollover_directive}{view_switching_directive}\n- If you need illustrative values, present them as labeled rollout scenarios or comparative examples rather than fake measured facts.\n- Keep the first visible artifact complete, request-specific, and visually intentional for {}.",
                    brief.audience,
                );
            }
            let requires_rollover_detail = super::brief_requires_rollover_detail(brief);
            let requires_view_switching = super::brief_requires_view_switching(brief);
            let layout_recipe = match candidate_seed % 3 {
                0 => {
                    "story-led hero, sticky section navigation, annotated timeline, and a detail drawer"
                }
                1 => {
                    "dashboard-led metrics rail, scenario controls, comparison cards, and an evidence panel"
                }
                _ => {
                    "editorial sections, guided tutorial stepper, interactive showcase cards, and a feedback summary"
                }
            };
            let concept_focus = summarized_guidance_terms(
                &brief.required_concepts,
                "the typed request concepts",
                4,
            );
            let interaction_focus = summarized_guidance_terms(
                &brief.required_interactions,
                "the required interactions",
                3,
            );
            let section_blueprint = html_first_paint_section_blueprint(brief);
            let evidence_plan = html_candidate_evidence_plan(brief, candidate_seed);
            let anchor_surface_directive = html_factual_anchor_surface_directive(brief);
            let interaction_distribution_directive =
                html_interaction_distribution_directive(brief);
            let sequence_browsing_directive = if super::brief_requires_sequence_browsing(brief) {
                "\n- When a requiredInteraction implies sequence browsing, timeline traversal, or scrolling through staged evidence, give it its own visible progression mechanism on first paint such as a stepper, previous/next controls, a scrubber, or a scroll-snap evidence rail. A static chart plus unrelated panel toggles does not satisfy sequence browsing."
                    .to_string()
            } else {
                String::new()
            };
            let rollover_mark_example = super::html_prompt_rollover_mark_example(brief);
            let exact_view_scaffold = super::html_prompt_exact_view_scaffold(brief);
            let two_view_example = super::html_prompt_two_view_example(brief);
            let rollover_directive = if requires_rollover_detail {
                format!(
                    "\n- When the brief calls for rollover or hover detail, include at least three visible SVG or DOM marks with data-detail text plus mouseenter/focus handlers that rewrite one shared detail panel inline. Give focusable marks tabindex=\"0\" when needed, and wire them with one collection pattern such as querySelectorAll('[data-detail]'). Buttons alone do not satisfy rollover.\n- A concrete rollover mark can look like {}; pair it with one shared detail node such as #detail-copy that the hover/focus handlers rewrite inline.",
                    rollover_mark_example
                )
            } else {
                String::new()
            };
            let combined_interaction_directive =
                if requires_view_switching && requires_rollover_detail {
                format!(
                    "\n- When the brief combines clickable view switching with rollover detail, keep both behaviors in the same artifact: render at least two pre-rendered view panels, keep one panel active on first paint, and also render visible data-detail marks inside the evidence views so the same shared detail panel updates on both button click and mark hover/focus.\n- A strong script shape here is querySelectorAll('button[data-view]') for controls, querySelectorAll('[data-view-panel]') for panels, querySelectorAll('[data-detail]') for marks, and one shared detail node such as #detail-copy that both handlers rewrite inline.\n- A safe exact scaffold is {} plus <aside><p id=\"detail-copy\">{} is selected by default.</p></aside>.\n- Keep data-view-panel as a literal HTML attribute on each panel element; a class token like class=\"data-view-panel\" does not count as a mapped panel.\n- If you use aria-controls, target the enclosing section/article/div panel rather than an inner SVG node or chart mark.\n- If you use Array methods such as find, map, or filter on queried controls or panels, wrap querySelectorAll results with Array.from first instead of calling array-only methods on a NodeList.\n- Keep exactly one mapped panel visible in the raw markup before any script runs; the remaining mapped panels may start hidden.\n- Do not trade one interaction family away while fixing the other.",
                    exact_view_scaffold,
                    brief
                        .factual_anchors
                        .first()
                        .map(|value| value.trim())
                        .filter(|value| !value.is_empty())
                        .unwrap_or("The first evidence view")
                )
                } else {
                    String::new()
                };
            format!(
                "- Use the candidate seed to vary composition. This candidate should follow the layout recipe: {layout_recipe}.\n- Build the first paint around this section blueprint: {section_blueprint}.\n- Build the first paint around a named control bar, a primary evidence region, and a shared detail or comparison panel.\n- A strong HTML pattern here is: request-specific hero section, control nav with real buttons, primary evidence article, secondary evidence article or comparison card, populated detail aside, and a short footer note.\n{evidence_plan}\n{anchor_surface_directive}\n{interaction_distribution_directive}\n- Derive visible controls and response regions from these brief concepts: {concept_focus}.\n- Make these required interactions tangible on first paint: {interaction_focus}.\n- Realize every requiredInteraction with visible controls that change content, swap views, reveal deeper detail, or compare scenarios inline.\n- Include at least two stateful controls such as buttons, tabs, segmented toggles, or clickable cards that update one shared detail, comparison, or explanation region.{sequence_browsing_directive}\n- Keep the hero and primary heading request-specific; synthesize the thesis in your own words instead of pasting artifactThesis verbatim as the headline.\n- Surface every requiredConcept in visible headings, labels, legends, captions, or callouts, not only in the title.\n- Turn factualAnchors and referenceHints into visible annotations, labels, legends, comparison rows, or evidence notes on first paint instead of burying them in generic prose.\n- Avoid the default textbook/tutorial shell of stacked sections that repeat the same copy-plus-box pattern for each concept.\n- Use one decisive visual metaphor, evidence rhythm, or interaction seam so the artifact feels specifically authored for this request rather than like a generic explainer page.\n- Make each sectioning region independently meaningful on first paint: every <section>, <article>, <aside>, or <footer> should contain a heading, body copy, data marks, or detail content rather than acting as an empty wrapper around future script output.\n- Ship interactive regions with actual first-paint content and data. Empty containers or comment-only handlers are not acceptable.\n- Render the default selected chart, label, detail state, and secondary evidence preview directly in the HTML markup before the script tag. JavaScript should switch, annotate, or toggle visible content, not create the only first-paint content from nothing.\n- Keep visible markup first: place the script after the closing </main> or at the end of <body>, not as a long head script before the surfaced sections.\n- Do not rely on DOMContentLoaded, innerHTML, appendChild, createElement, template-string HTML injection, or canvas drawing to create the first visible chart, scorecard, comparison panel, or alternate evidence view from an empty target. Those techniques may enhance an already-populated region, but they must not be the sole first-paint implementation.\n- Prefer pre-rendered evidence articles, comparison cards, legend tables, or detail blocks already present in the DOM. Controls should toggle hidden/data-active/aria-selected state or rewrite one shared detail panel rather than rebuilding the whole view with innerHTML.\n- When the artifact uses view-switching controls, pair them with matching pre-rendered panels already in the DOM, for example {} and a panels collection selected before toggling hidden state.\n- Keep data-view-panel as a literal HTML attribute on each panel element; a class token like class=\"data-view-panel\" does not satisfy the mapping.\n- Prefer dataset comparisons such as panel.dataset.viewPanel !== button.dataset.view instead of building a querySelector string with nested quoted fragments.\n- If you use aria-controls, target the enclosing section/article/div panel rather than an inner SVG node or chart mark.\n- If you use Array methods such as find, map, or filter on queried controls or panels, wrap querySelectorAll results with Array.from first instead of calling array-only methods on a NodeList.\n- Keep exactly one mapped panel visible in the raw markup before any script runs; the remaining mapped panels may start hidden.\n- Do not point every button only at the shared detail panel with aria-controls; the shared detail panel supports the per-view panels and does not replace them.\n- Buttons that only call alert(), submit nowhere, or navigate away do not satisfy requiredInteractions.\n- Do not use fragment-jump anchors as the primary interaction model. Prefer buttons, tabs, or clickable cards that rewrite one shared detail, comparison, or explanation region inline.\n- Build charts, diagrams, or explainers with inline SVG, canvas, or DOM/CSS. Do not rely on external libraries, undefined globals, or remote placeholder media.\n- Prefer inline SVG or DOM/CSS data marks over blank canvas placeholders. If you use canvas, the first paint still needs visible drawn content or an adjacent data fallback.\n- Every chart or diagram must include visible labels, legend text, or accessible labels on first paint. Decorative rings or unlabeled shapes are not enough.\n- When charts, metrics, or data visualizations are part of the brief, first paint must show at least two distinct evidence views or chart families tied to different request concepts. Use one primary visualization with at least three labeled marks plus a second populated evidence region tied to a different brief concept or factual anchor inline. One chart plus generic prose is insufficient.\n- Each visible chart or evidence family should carry multiple request-grounded marks, rows, or milestone steps with labels or captions; a single generic bar or rect does not satisfy a chart-driven brief.\n- A populated secondary evidence surface is not a single sentence paragraph. Use a second SVG, a comparison list or table, or a metric-card rail with at least three labeled items or rows.\n- If a wrapper is labeled or styled as a chart, metric, or evidence panel, populate it with structured evidence rather than overview prose alone.\n- Shared detail updates should surface the underlying metric, milestone, or evidence sentence from the current mark or control, not just echo a raw panel id or button label.{rollover_directive}{combined_interaction_directive}\n- A valid two-view first paint can pair {} Empty mount divs like <div id=\"usage-chart\"></div> do not count as the second evidence view.\n- Keep the non-selected or secondary evidence view visible as a preview, comparison card, secondary article, legend table, or score rail so the artifact reads as multi-view before any click.\n- Never include placeholder comments such as <!-- chart goes here -->, TODO markers, malformed button markup, or references to DOM ids that are not present in the markup.\n- Prefer controls that switch or annotate a shared detail panel, comparison rail, or evidence tray instead of a top-nav list that only scrolls.\n- Each control must map to a pre-rendered view, panel, or detail payload that already exists in the markup; do not wire buttons to nonexistent future containers.\n- If you attach handlers to multiple controls, marks, or cards, select them as a collection such as querySelectorAll before using forEach or similar iteration methods.\n- Make the default selected state complete on first paint so the artifact reads as usable before any click.\n- If the brief requires both view switching and rollover detail, preserve both interaction families through every repair pass instead of rewriting the artifact around only one of them.\n- If you need illustrative values, present them as labeled rollout scenarios or comparative examples rather than fake measured facts.\n- Replace filler testimonials or stock review copy with request-specific notes, observations, or rollout evidence summaries.\n- Include a short usage cue when interactions are not obvious on first paint.\n- Keep the first visible artifact complete and request-specific for {}.",
                exact_view_scaffold,
                two_view_example,
                brief.audience,
            )
        }
        StudioRendererKind::JsxSandbox => {
            let layout_recipe = match candidate_seed % 2 {
                0 => "control panel, primary visualization, and inspectable detail tray",
                _ => "guided flow, scenario switcher, and stateful summary rail",
            };
            format!(
                "- Use the candidate seed to vary component composition. This candidate should follow the layout recipe: {layout_recipe}.\n- Make requiredInteractions visible through real component state, not placeholder handlers.\n- Surface requiredConcepts in labels, headings, and summary copy so the artifact stays request-faithful on first paint."
            )
        }
        StudioRendererKind::Svg => {
            let composition_recipe = match candidate_seed % 2 {
                0 => "layered poster composition with a focal diagram and supporting labels",
                _ => "data-forward composition with a central motif, callout labels, and supporting legends",
            };
            format!(
                "- Use the candidate seed to vary the SVG composition. This candidate should follow the composition recipe: {composition_recipe}.\n- Surface the differentiating request concepts with labels, annotations, and hierarchy instead of a generic decorative shell.\n- Build a full composition, not a title card: use at least six visible SVG content elements drawn from text, path, rect, circle, line, polygon, or comparable marks.\n- Pair the focal motif with supporting labels, callouts, or legend rows that make multiple request concepts readable on first paint.\n- Do not stop at one background shape plus one headline; include layered supporting marks or diagrammatic structure that earns the primary visual view."
            )
        }
        StudioRendererKind::PdfEmbed => {
            let concept_focus = summarized_guidance_terms(
                &brief.required_concepts,
                "the typed request concepts",
                5,
            );
            let anchor_focus = summarized_guidance_terms(
                &brief.factual_anchors,
                "the typed factual anchors",
                4,
            );
            format!(
                "- Treat the PDF body as polished plain document text that Studio will compile into a PDF.\n- Do not emit LaTeX, TeX commands, markdown fences, HTML tags, or any wrapper format; write plain document text only.\n- Write at least 120 words across at least five non-empty sections, separated by blank lines.\n- Use a compact briefing structure with a title, short executive summary, explicit section headings, bullet lists, and a final next-steps or risks block.\n- Include at minimum an executive summary plus three request-grounded body sections and one closing section for next steps, risks, or decisions.\n- Put every section heading on its own short line with no trailing colon, for example Executive Summary, Project Scope, Target Audience, Marketing Strategy, Timeline and Milestones, and Next Steps and Risks.\n- Separate each heading block with a blank line so the rendered PDF keeps visible section breaks.\n- Do not use square-bracket placeholder tokens such as [Detailed description] or [List of objectives]; every bullet and row must contain concrete request-grounded content.\n- Surface these request concepts as named sections, bullets, or metric callouts: {concept_focus}.\n- Turn these factual anchors into labeled bullets, milestone rows, or a compact text table instead of dense prose: {anchor_focus}.\n- Prefer concise bullets, milestone lists, and compact comparison rows over long paragraphs.\n- If the brief asks for charts or graphs, realize them as compact metric tables, milestone grids, or labeled score rows inside the document text instead of promising unavailable graphics."
            )
        }
        StudioRendererKind::DownloadCard => {
            let concept_focus = summarized_guidance_terms(
                &brief.required_concepts,
                "the request-grounded deliverables",
                4,
            );
            format!(
                "- Produce a truthful downloadable bundle with non-empty export files only; do not mark any file renderable.\n- When the request implies a README or notes file, include a non-empty README.md that explains the bundle contents and how each file maps to the request.\n- When the bundle includes a CSV export, give it a header row plus at least two data rows with request-grounded values.\n- Prefer a small bundle with clear filenames, such as README.md plus one or more exports, over placeholder shells.\n- Keep the bundle contents visibly grounded in these request concepts: {concept_focus}."
            )
        }
        _ => "- Keep the artifact request-grounded, complete on first paint, and faithful to the typed brief.".to_string(),
    }
}

fn html_candidate_evidence_plan(brief: &StudioArtifactBrief, candidate_seed: u64) -> String {
    let topics = html_brief_evidence_topics(brief);
    let rotated_topics = rotated_guidance_terms(&topics, candidate_seed as usize, 4);
    let primary_focus = rotated_topics
        .first()
        .cloned()
        .unwrap_or_else(|| "the primary rollout evidence".to_string());
    let secondary_focus = rotated_topics
        .get(1)
        .cloned()
        .unwrap_or_else(|| "a supporting comparison topic".to_string());
    let detail_focus = rotated_topics
        .iter()
        .take(3)
        .cloned()
        .collect::<Vec<_>>()
        .join(", ");
    let detail_focus = if detail_focus.is_empty() {
        "the brief evidence topics".to_string()
    } else {
        detail_focus
    };
    let control_terms = rotated_guidance_terms(&topics, candidate_seed as usize + 1, 3);
    let control_focus = if control_terms.is_empty() {
        "the brief evidence topics".to_string()
    } else {
        control_terms.join(", ")
    };
    let secondary_surface = match candidate_seed % 3 {
        0 => "comparison article",
        1 => "metric-card rail",
        _ => "score table or evidence list",
    };
    let tertiary_focus = rotated_topics.get(2).cloned();
    let tertiary_control_directive = tertiary_focus
        .as_ref()
        .map(|focus| {
            format!(
                "- Use a third labeled control, tab, or clickable card for {focus} when the brief exposes three or more evidence topics, and keep that topic visible as a preview, secondary panel, or detail payload instead of dropping it entirely."
            )
        })
        .unwrap_or_default();
    let combined_interaction_directive = if super::brief_requires_view_switching(brief)
        && super::brief_requires_rollover_detail(brief)
    {
        if studio_modal_first_html_enabled() {
            "- Keep the interaction model combined on first paint: view-switching should move between authored scenes or states, and visible inspectable marks should reveal deeper context inline without collapsing the whole artifact into one repeated control row."
                .to_string()
        } else {
            "- Keep the interaction model combined on first paint: buttons or tabs should switch pre-rendered [data-view-panel] views, and visible [data-detail] marks inside those views should update the same shared detail panel on hover or focus."
                .to_string()
        }
    } else {
        String::new()
    };

    if studio_modal_first_html_enabled() {
        return format!(
            "- Ground this candidate in a concrete evidence plan: primary evidence on {primary_focus}; secondary evidence on {secondary_focus}; inline explanation anchored in {detail_focus}.\n- Use visible control labels, section headings, legends, or comparison labels derived from these brief topics: {control_focus}.\n- Keep both the primary evidence view and a populated {secondary_surface} visible on first paint so the artifact reads as multi-view before any click.\n- Make the primary evidence view an inline SVG or DOM data-mark visualization for {primary_focus}. Use a separate populated {secondary_surface} for {secondary_focus}; it may be a second SVG, annotated comparison list, metric card grid, or score table, but it must stay visible on first paint.\n- Do not satisfy the secondary evidence surface with a bare paragraph. Use structured evidence such as multiple labeled rows, comparison bullets, metric cards, or a second SVG tied to {secondary_focus}.\n- Let captions, callouts, overlays, or nearby contextual copy explain {detail_focus} when buttons, cards, marks, or progression controls are activated.\n- If clickable navigation helps, move between authored scenes, states, or sections already present in the markup; do not default to the same detached detail-panel scaffold unless the request truly benefits from it.\n{combined_interaction_directive}\n{tertiary_control_directive}",
        );
    }

    format!(
        "- Ground this candidate in a concrete evidence plan: primary evidence on {primary_focus}; secondary evidence on {secondary_focus}; shared detail anchored in {detail_focus}.\n- Use visible control labels, section headings, legends, or comparison labels derived from these brief topics: {control_focus}.\n- Keep both the primary evidence view and a populated {secondary_surface} visible on first paint so the artifact reads as multi-view before any click.\n- Make the primary evidence view an inline SVG or DOM data-mark visualization for {primary_focus}. Use a separate populated {secondary_surface} for {secondary_focus}; it may be a second SVG, annotated comparison list, metric card grid, or score table, but it must stay visible on first paint.\n- Do not satisfy the secondary evidence surface with a bare paragraph. Use structured evidence such as multiple labeled rows, comparison bullets, metric cards, or a second SVG tied to {secondary_focus}.\n- Let the shared detail panel compare or explain {detail_focus} and update inline when buttons, cards, or marks are activated.\n- For clickable navigation, use explicit static mappings that point at pre-rendered panel ids already present in the markup. A safe pattern is {}. Keep data-view-panel as a literal HTML attribute on the panel element itself; a class token like class=\"data-view-panel\" does not satisfy the mapping. Toggle hidden, data-active, or aria-selected state instead of synthesizing target ids with string concatenation at runtime.\n- Static data-view, aria-controls, or data-target attributes do not count on their own; wire click handlers that toggle hidden, aria-selected, aria-hidden, data-active, or comparable state on the mapped panel wrappers.\n- Do not use class names like class=\"overview-panel\" or class=\"data-view-panel\" as a substitute for literal id/data-view-panel attributes on the panel wrapper.\n{combined_interaction_directive}\n{tertiary_control_directive}",
        super::html_prompt_view_mapping_pattern(brief),
    )
}

fn html_factual_anchor_surface_directive(brief: &StudioArtifactBrief) -> String {
    let anchors = brief
        .factual_anchors
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if anchors.is_empty() {
        return String::new();
    }

    let mut directives = vec![format!(
        "- Dedicate a first-paint evidence surface directly to this factual anchor: {}. Make that anchor inspectable through visible labels, marks, annotations, captions, or comparison rows instead of generic overview prose.",
        anchors[0]
    )];
    if let Some(second_anchor) = anchors.get(1) {
        directives.push(format!(
            "- Dedicate a second named evidence surface or comparison rail directly to this factual anchor: {}. Keep that surface visible on first paint as a preview, metric rail, comparison article, or secondary evidence panel rather than collapsing it into one generic summary block.",
            second_anchor
        ));
    }
    if let Some(reference_hint) = brief
        .reference_hints
        .iter()
        .map(|item| item.trim())
        .find(|item| !item.is_empty())
    {
        directives.push(format!(
            "- Use supporting reference context like {} as annotations, comparative callouts, or provenance notes, but do not let it replace the top factual anchors as the main evidence surfaces.",
            reference_hint
        ));
    }

    directives.join("\n")
}

fn html_interaction_distribution_directive(brief: &StudioArtifactBrief) -> String {
    let interactions = brief
        .required_interactions
        .iter()
        .map(|item| item.trim())
        .filter(|item| !item.is_empty())
        .collect::<Vec<_>>();
    if interactions.len() < 2 {
        return String::new();
    }

    format!(
        "- This brief carries multiple interaction demands ({}) so distribute them across the artifact: keep one explicit control-bar interaction, plus at least one in-evidence inspection or input behavior on visible marks, cards, chips, form fields, or list items. Do not collapse every interaction into the same button row or a single generic panel toggle.",
        interactions.join(", ")
    )
}

fn html_brief_evidence_topics(brief: &StudioArtifactBrief) -> Vec<String> {
    let mut topics = Vec::<String>::new();
    let mut seen = HashSet::<String>::new();

    for collection in [
        &brief.factual_anchors,
        &brief.required_concepts,
        &brief.reference_hints,
    ] {
        for item in collection {
            for fragment in item
                .split(|ch| matches!(ch, ',' | ';' | '\n'))
                .map(str::trim)
                .filter(|fragment| !fragment.is_empty())
            {
                let key = fragment.to_ascii_lowercase();
                if seen.insert(key) {
                    topics.push(fragment.to_string());
                }
            }
        }
    }

    topics
}

fn rotated_guidance_terms(topics: &[String], offset: usize, count: usize) -> Vec<String> {
    if topics.is_empty() || count == 0 {
        return Vec::new();
    }

    let start = offset % topics.len();
    (0..topics.len())
        .map(|index| topics[(start + index) % topics.len()].clone())
        .take(count.min(topics.len()))
        .collect()
}

pub fn build_studio_artifact_materialization_repair_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    build_studio_artifact_materialization_repair_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        None,
        None,
        &[],
        &[],
        edit_intent,
        refinement,
        candidate_id,
        candidate_seed,
        raw_output,
        failure,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

pub(super) fn build_studio_artifact_materialization_repair_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate_id: &str,
    candidate_seed: u64,
    raw_output: &str,
    failure: &str,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_materialization_prompt(request.renderer, runtime_kind);
    let resolved_blueprint = blueprint
        .cloned()
        .unwrap_or_else(|| derive_studio_artifact_blueprint(request, brief));
    let resolved_artifact_ir = artifact_ir
        .cloned()
        .unwrap_or_else(|| compile_studio_artifact_ir(request, brief, &resolved_blueprint));
    let request_json =
        serialize_materialization_prompt_json(request, "Studio artifact request", compact_prompt)?;
    let brief_json =
        serialize_materialization_prompt_json(brief, "Studio artifact brief", compact_prompt)?;
    let blueprint_json = serialize_materialization_prompt_json(
        &resolved_blueprint,
        "Studio artifact blueprint",
        compact_prompt,
    )?;
    let artifact_ir_json = serialize_materialization_prompt_json(
        &resolved_artifact_ir,
        "Studio artifact IR",
        compact_prompt,
    )?;
    let selected_skills_json = serialize_materialization_prompt_json(
        &studio_artifact_selected_skill_prompt_view(selected_skills),
        "Studio selected skill guidance",
        compact_prompt,
    )?;
    let retrieved_exemplars_json = serialize_materialization_prompt_json(
        &studio_artifact_exemplar_prompt_view(retrieved_exemplars),
        "Studio retrieved exemplars",
        compact_prompt,
    )?;
    let surface_contracts = studio_surface_contract_prompt_bundle(
        brief,
        &resolved_blueprint,
        &resolved_artifact_ir,
        selected_skills,
        candidate_seed,
    );
    let promoted_design_spine_json = serialize_materialization_prompt_json(
        &surface_contracts.design_spine,
        surface_contracts.design_label,
        compact_prompt,
    )?;
    let scaffold_contract_json = serialize_materialization_prompt_json(
        &surface_contracts.scaffold_contract,
        surface_contracts.scaffold_label,
        compact_prompt,
    )?;
    let component_pack_contract_json = serialize_materialization_prompt_json(
        &surface_contracts.component_packs,
        surface_contracts.component_label,
        compact_prompt,
    )?;
    let edit_intent_json = serialize_materialization_prompt_json(
        &edit_intent,
        "Studio artifact edit intent",
        compact_prompt,
    )?;
    let refinement_json = serialize_materialization_prompt_json(
        &studio_artifact_refinement_context_view(refinement),
        "Studio refinement context",
        compact_prompt,
    )?;
    let renderer_guidance = studio_artifact_renderer_authoring_guidance_for_runtime(
        request,
        brief,
        candidate_seed,
        runtime_kind,
    );
    let scaffold_execution_digest = surface_contracts.execution_digest;
    let scaffold_execution_block = if scaffold_execution_digest.is_empty() {
        String::new()
    } else {
        format!(
            "\n\nScaffold execution digest:\n{}",
            if compact_prompt {
                truncate_materialization_focus_text(&scaffold_execution_digest, 180)
            } else {
                scaffold_execution_digest
            }
        )
    };
    let failure_directives =
        super::studio_artifact_materialization_failure_directives(request, brief, failure);
    let schema_contract =
        studio_artifact_materialization_schema_contract_for_runtime(request.renderer, runtime_kind);
    if compact_prompt {
        let request_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_materialization_request_focus(request),
            "Studio artifact request focus",
            true,
        )?;
        let brief_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_materialization_brief_focus(brief),
            "Studio artifact brief focus",
            true,
        )?;
        let interaction_contract_json = serialize_materialization_prompt_json(
            &super::studio_artifact_interaction_contract(brief),
            "Studio interaction contract",
            true,
        )?;
        let edit_intent_focus_json = serialize_materialization_prompt_json(
            &edit_intent,
            "Studio artifact edit intent focus",
            true,
        )?;
        let refinement_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_refinement_context_focus(refinement),
            "Studio refinement context focus",
            true,
        )?;
        let previous_candidate_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_materialization_repair_candidate_focus(raw_output, request),
            "Studio artifact repair candidate focus",
            true,
        )?;
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Studio's typed artifact materialization repairer. Patch the previous candidate into a schema-valid JSON artifact payload. Preserve the strongest valid request-specific structure instead of restarting from a fresh shell. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus JSON:\n{}\n\nArtifact brief focus JSON:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent focus JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nPrevious candidate focus JSON:\n{}\n\nThe previous artifact payload was rejected.\nFailure:\n{}\n\nFailure-specific repair directives:\n{}\n{}\n\nRenderer-native authoring guidance:\n{}\n\nRepair the payload so it is fully schema-valid, keeps the strongest working structure, and remains request-faithful. Return JSON only.\n\n{}",
                    title,
                    intent,
                    request_focus_json,
                    brief_focus_json,
                    interaction_contract_json,
                    edit_intent_focus_json,
                    refinement_focus_json,
                    candidate_id,
                    candidate_seed,
                    previous_candidate_focus_json,
                    compact_local_html_directives_text(failure),
                    compact_local_html_directives_text(&failure_directives),
                    scaffold_execution_block,
                    renderer_guidance,
                    schema_contract,
                )
            }
        ]));
    }
    let previous_candidate_json = serialize_materialization_prompt_json(
        &materialization_repair_candidate_view(raw_output, request),
        "Studio artifact repair candidate view",
        compact_prompt,
    )?;
    let raw_output_preview = truncate_candidate_failure_preview(raw_output, 3600)
        .unwrap_or_else(|| "(empty)".to_string());
    let design_label = format!("{} JSON", surface_contracts.design_label);
    let scaffold_label = format!("{} JSON", surface_contracts.scaffold_label);
    let component_label = format!("{} JSON", surface_contracts.component_label);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact materialization repairer. Repair the candidate into a schema-valid JSON artifact payload. If the previous output already contains a usable candidate shape, patch it instead of restarting from a fresh shell. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nArtifact brief JSON:\n{}\n\nArtifact blueprint JSON:\n{}\n\nArtifact IR JSON:\n{}\n\nSelected skill guidance JSON:\n{}\n\nRetrieved exemplar JSON:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nThe previous artifact payload was rejected.\nFailure:\n{}\n\nPrevious candidate view JSON:\n{}\n\nPrevious raw output excerpt:\n{}\n{}\n\nRenderer-native authoring guidance:\n{}\n\nFailure-specific repair directives:\n{}\n\nRepair the payload so it is fully schema-valid and request-faithful. Preserve the strongest valid content from the previous attempt when possible.\n\n{}",
                title,
                intent,
                request_json,
                brief_json,
                blueprint_json,
                artifact_ir_json,
                selected_skills_json,
                retrieved_exemplars_json,
                design_label,
                promoted_design_spine_json,
                scaffold_label,
                scaffold_contract_json,
                component_label,
                component_pack_contract_json,
                edit_intent_json,
                refinement_json,
                candidate_id,
                candidate_seed,
                failure,
                previous_candidate_json,
                raw_output_preview,
                scaffold_execution_block,
                renderer_guidance,
                failure_directives,
                schema_contract,
            )
        }
    ]))
}

pub fn build_studio_artifact_candidate_refinement_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate: &StudioGeneratedArtifactPayload,
    judge: &StudioArtifactJudgeResult,
    candidate_id: &str,
    candidate_seed: u64,
) -> Result<serde_json::Value, String> {
    build_studio_artifact_candidate_refinement_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        None,
        None,
        &[],
        &[],
        edit_intent,
        refinement,
        candidate,
        judge,
        candidate_id,
        candidate_seed,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

pub(crate) fn build_studio_artifact_candidate_refinement_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate: &StudioGeneratedArtifactPayload,
    judge: &StudioArtifactJudgeResult,
    candidate_id: &str,
    candidate_seed: u64,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_materialization_prompt(request.renderer, runtime_kind);
    let resolved_blueprint = blueprint
        .cloned()
        .unwrap_or_else(|| derive_studio_artifact_blueprint(request, brief));
    let resolved_artifact_ir = artifact_ir
        .cloned()
        .unwrap_or_else(|| compile_studio_artifact_ir(request, brief, &resolved_blueprint));
    let request_json =
        serialize_materialization_prompt_json(request, "Studio artifact request", compact_prompt)?;
    let brief_json =
        serialize_materialization_prompt_json(brief, "Studio artifact brief", compact_prompt)?;
    let blueprint_json = serialize_materialization_prompt_json(
        &resolved_blueprint,
        "Studio artifact blueprint",
        compact_prompt,
    )?;
    let artifact_ir_json = serialize_materialization_prompt_json(
        &resolved_artifact_ir,
        "Studio artifact IR",
        compact_prompt,
    )?;
    let selected_skills_json = serialize_materialization_prompt_json(
        &studio_artifact_selected_skill_prompt_view(selected_skills),
        "Studio selected skill guidance",
        compact_prompt,
    )?;
    let retrieved_exemplars_json = serialize_materialization_prompt_json(
        &studio_artifact_exemplar_prompt_view(retrieved_exemplars),
        "Studio retrieved exemplars",
        compact_prompt,
    )?;
    let surface_contracts = studio_surface_contract_prompt_bundle(
        brief,
        &resolved_blueprint,
        &resolved_artifact_ir,
        selected_skills,
        candidate_seed,
    );
    let promoted_design_spine_json = serialize_materialization_prompt_json(
        &surface_contracts.design_spine,
        surface_contracts.design_label,
        compact_prompt,
    )?;
    let scaffold_contract_json = serialize_materialization_prompt_json(
        &surface_contracts.scaffold_contract,
        surface_contracts.scaffold_label,
        compact_prompt,
    )?;
    let component_pack_contract_json = serialize_materialization_prompt_json(
        &surface_contracts.component_packs,
        surface_contracts.component_label,
        compact_prompt,
    )?;
    let interaction_contract_json = serialize_materialization_prompt_json(
        &super::studio_artifact_interaction_contract(brief),
        "Studio interaction contract",
        compact_prompt,
    )?;
    let edit_intent_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &edit_intent,
            "Studio artifact edit intent focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(&edit_intent, "Studio artifact edit intent", false)?
    };
    let refinement_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &compact_local_html_refinement_context_focus(refinement),
            "Studio refinement context focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(
            &studio_artifact_refinement_context_view(refinement),
            "Studio refinement context",
            false,
        )?
    };
    let candidate_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &compact_local_html_refinement_candidate_focus(candidate),
            "Studio artifact candidate focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(
            &studio_artifact_refinement_candidate_view(candidate),
            "Studio artifact candidate",
            false,
        )?
    };
    let judge_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &compact_local_html_refinement_judge_focus(judge),
            "Studio artifact judge focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(judge, "Studio artifact judge result", false)?
    };
    let renderer_guidance = studio_artifact_renderer_authoring_guidance_for_runtime(
        request,
        brief,
        candidate_seed,
        runtime_kind,
    );
    let scaffold_execution_digest = surface_contracts.execution_digest;
    let scaffold_execution_block = if scaffold_execution_digest.is_empty() {
        String::new()
    } else {
        format!(
            "\n\nScaffold execution digest:\n{}",
            if compact_prompt {
                truncate_materialization_focus_text(&scaffold_execution_digest, 180)
            } else {
                scaffold_execution_digest
            }
        )
    };
    let refinement_directives =
        super::studio_artifact_candidate_refinement_directives(request, brief, judge);
    let refinement_directives = if compact_prompt {
        compact_local_html_directives_text(&refinement_directives)
    } else {
        refinement_directives
    };
    let schema_contract =
        studio_artifact_materialization_schema_contract_for_runtime(request.renderer, runtime_kind);
    if compact_prompt {
        let request_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_materialization_request_focus(request),
            "Studio artifact request focus",
            true,
        )?;
        let brief_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_materialization_brief_focus(brief),
            "Studio artifact brief focus",
            true,
        )?;
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Studio's typed artifact refiner. Patch the current candidate in place to resolve the judge's cited contradictions while preserving working structure and strong request-specific content. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus JSON:\n{}\n\nArtifact brief focus JSON:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent focus JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nCurrent candidate focus JSON:\n{}\n\nAcceptance judgment focus JSON:\n{}\n\nPatch the current candidate so it keeps the strongest working structure, but fixes the cited request-faithfulness, interaction, hierarchy, and completeness gaps. Preserve file paths unless they are actively wrong.\n\nRefinement output contract:\nReturn the patched artifact inside the exact JSON schema below; do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object.\n\nRefinement directives:\n{}\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
                    title,
                    intent,
                    request_focus_json,
                    brief_focus_json,
                    interaction_contract_json,
                    edit_intent_json,
                    refinement_json,
                    candidate_id,
                    candidate_seed,
                    candidate_json,
                    judge_json,
                    refinement_directives,
                    scaffold_execution_block,
                    renderer_guidance,
                    schema_contract,
                )
            }
        ]));
    }
    let design_label = format!("{} JSON", surface_contracts.design_label);
    let scaffold_label = format!("{} JSON", surface_contracts.scaffold_label);
    let component_label = format!("{} JSON", surface_contracts.component_label);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact refiner. Patch the current candidate in place to resolve the judge's cited contradictions while preserving working structure and strong request-specific content. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nArtifact brief JSON:\n{}\n\nArtifact blueprint JSON:\n{}\n\nArtifact IR JSON:\n{}\n\nSelected skill guidance JSON:\n{}\n\nRetrieved exemplar JSON:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nCurrent candidate JSON:\n{}\n\nAcceptance judgment JSON:\n{}\n\nPatch the current candidate so it keeps the strongest working structure, but fixes the cited request-faithfulness, interaction, hierarchy, and completeness gaps. Preserve file paths unless they are actively wrong.\n\nRefinement output contract:\nReturn the patched artifact inside the exact JSON schema below; do not answer with raw HTML, raw JSX, raw SVG, or prose outside the JSON object.\n\nRefinement directives:\n{}\n{}\n\nRenderer-native authoring guidance:\n{}\n\n{}",
                title,
                intent,
                request_json,
                brief_json,
                blueprint_json,
                artifact_ir_json,
                selected_skills_json,
                retrieved_exemplars_json,
                design_label,
                promoted_design_spine_json,
                scaffold_label,
                scaffold_contract_json,
                component_label,
                component_pack_contract_json,
                interaction_contract_json,
                edit_intent_json,
                refinement_json,
                candidate_id,
                candidate_seed,
                candidate_json,
                judge_json,
                refinement_directives,
                scaffold_execution_block,
                renderer_guidance,
                schema_contract,
            )
        }
    ]))
}

pub fn build_studio_artifact_candidate_refinement_repair_prompt(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate: &StudioGeneratedArtifactPayload,
    judge: &StudioArtifactJudgeResult,
    candidate_id: &str,
    candidate_seed: u64,
    raw_output: &str,
    failure: &str,
) -> Result<serde_json::Value, String> {
    build_studio_artifact_candidate_refinement_repair_prompt_for_runtime(
        title,
        intent,
        request,
        brief,
        None,
        None,
        &[],
        &[],
        edit_intent,
        refinement,
        candidate,
        judge,
        candidate_id,
        candidate_seed,
        raw_output,
        failure,
        StudioRuntimeProvenanceKind::RealRemoteModelRuntime,
    )
}

fn build_studio_artifact_candidate_refinement_repair_prompt_for_runtime(
    title: &str,
    intent: &str,
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    blueprint: Option<&StudioArtifactBlueprint>,
    artifact_ir: Option<&StudioArtifactIR>,
    selected_skills: &[StudioArtifactSelectedSkill],
    retrieved_exemplars: &[StudioArtifactExemplar],
    edit_intent: Option<&StudioArtifactEditIntent>,
    refinement: Option<&StudioArtifactRefinementContext>,
    candidate: &StudioGeneratedArtifactPayload,
    judge: &StudioArtifactJudgeResult,
    candidate_id: &str,
    candidate_seed: u64,
    raw_output: &str,
    failure: &str,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Result<serde_json::Value, String> {
    let compact_prompt = compact_local_html_materialization_prompt(request.renderer, runtime_kind);
    let resolved_blueprint = blueprint
        .cloned()
        .unwrap_or_else(|| derive_studio_artifact_blueprint(request, brief));
    let resolved_artifact_ir = artifact_ir
        .cloned()
        .unwrap_or_else(|| compile_studio_artifact_ir(request, brief, &resolved_blueprint));
    let request_json =
        serialize_materialization_prompt_json(request, "Studio artifact request", compact_prompt)?;
    let brief_json =
        serialize_materialization_prompt_json(brief, "Studio artifact brief", compact_prompt)?;
    let blueprint_json = serialize_materialization_prompt_json(
        &resolved_blueprint,
        "Studio artifact blueprint",
        compact_prompt,
    )?;
    let artifact_ir_json = serialize_materialization_prompt_json(
        &resolved_artifact_ir,
        "Studio artifact IR",
        compact_prompt,
    )?;
    let selected_skills_json = serialize_materialization_prompt_json(
        &studio_artifact_selected_skill_prompt_view(selected_skills),
        "Studio selected skill guidance",
        compact_prompt,
    )?;
    let retrieved_exemplars_json = serialize_materialization_prompt_json(
        &studio_artifact_exemplar_prompt_view(retrieved_exemplars),
        "Studio retrieved exemplars",
        compact_prompt,
    )?;
    let surface_contracts = studio_surface_contract_prompt_bundle(
        brief,
        &resolved_blueprint,
        &resolved_artifact_ir,
        selected_skills,
        candidate_seed,
    );
    let promoted_design_spine_json = serialize_materialization_prompt_json(
        &surface_contracts.design_spine,
        surface_contracts.design_label,
        compact_prompt,
    )?;
    let scaffold_contract_json = serialize_materialization_prompt_json(
        &surface_contracts.scaffold_contract,
        surface_contracts.scaffold_label,
        compact_prompt,
    )?;
    let component_pack_contract_json = serialize_materialization_prompt_json(
        &surface_contracts.component_packs,
        surface_contracts.component_label,
        compact_prompt,
    )?;
    let interaction_contract_json = serialize_materialization_prompt_json(
        &super::studio_artifact_interaction_contract(brief),
        "Studio interaction contract",
        compact_prompt,
    )?;
    let edit_intent_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &edit_intent,
            "Studio artifact edit intent focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(&edit_intent, "Studio artifact edit intent", false)?
    };
    let refinement_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &compact_local_html_refinement_context_focus(refinement),
            "Studio refinement context focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(
            &studio_artifact_refinement_context_view(refinement),
            "Studio refinement context",
            false,
        )?
    };
    let candidate_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &compact_local_html_refinement_candidate_focus(candidate),
            "Studio artifact candidate focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(
            &studio_artifact_refinement_candidate_view(candidate),
            "Studio artifact candidate",
            false,
        )?
    };
    let judge_json = if compact_prompt {
        serialize_materialization_prompt_json(
            &compact_local_html_refinement_judge_focus(judge),
            "Studio artifact judge focus",
            true,
        )?
    } else {
        serialize_materialization_prompt_json(judge, "Studio artifact judge result", false)?
    };
    let renderer_guidance = studio_artifact_renderer_authoring_guidance_for_runtime(
        request,
        brief,
        candidate_seed,
        runtime_kind,
    );
    let scaffold_execution_digest = surface_contracts.execution_digest;
    let scaffold_execution_block = if scaffold_execution_digest.is_empty() {
        String::new()
    } else {
        format!(
            "\n\nScaffold execution digest:\n{}",
            if compact_prompt {
                truncate_materialization_focus_text(&scaffold_execution_digest, 320)
            } else {
                scaffold_execution_digest
            }
        )
    };
    let failure_directives =
        super::studio_artifact_materialization_failure_directives(request, brief, failure);
    let schema_contract =
        studio_artifact_materialization_schema_contract_for_runtime(request.renderer, runtime_kind);
    if compact_prompt {
        let request_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_materialization_request_focus(request),
            "Studio artifact request focus",
            true,
        )?;
        let brief_focus_json = serialize_materialization_prompt_json(
            &compact_local_html_materialization_brief_focus(brief),
            "Studio artifact brief focus",
            true,
        )?;
        return Ok(json!([
            {
                "role": "system",
                "content": "You are Studio's typed artifact refinement repairer. Repair the refined candidate into a schema-valid patch that resolves the cited contradictions while preserving the current artifact's strongest valid structure. Output JSON only."
            },
            {
                "role": "user",
                "content": format!(
                    "Title:\n{}\n\nRequest:\n{}\n\nArtifact request focus JSON:\n{}\n\nArtifact brief focus JSON:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent focus JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nCurrent candidate focus JSON:\n{}\n\nAcceptance judgment focus JSON:\n{}\n\nThe previous refinement payload was rejected.\nFailure:\n{}\n\nPrevious raw refinement output:\n{}\n{}\n\nRenderer-native authoring guidance:\n{}\n\nFailure-specific repair directives:\n{}\n\nRepair the refinement payload so it stays request-faithful, preserves working structure, and fully validates.\n\n{}",
                    title,
                    intent,
                    request_focus_json,
                    brief_focus_json,
                    interaction_contract_json,
                    edit_intent_json,
                    refinement_json,
                    candidate_id,
                    candidate_seed,
                    candidate_json,
                    judge_json,
                    failure,
                    truncate_candidate_failure_preview(raw_output, 1600)
                        .unwrap_or_else(|| "(empty)".to_string()),
                    scaffold_execution_block,
                    renderer_guidance,
                    failure_directives,
                    schema_contract,
                )
            }
        ]));
    }
    let design_label = format!("{} JSON", surface_contracts.design_label);
    let scaffold_label = format!("{} JSON", surface_contracts.scaffold_label);
    let component_label = format!("{} JSON", surface_contracts.component_label);
    Ok(json!([
        {
            "role": "system",
            "content": "You are Studio's typed artifact refinement repairer. Repair the refined candidate into a schema-valid patch that resolves the cited contradictions while preserving the current artifact's strongest valid structure. Output JSON only."
        },
        {
            "role": "user",
            "content": format!(
                "Title:\n{}\n\nRequest:\n{}\n\nArtifact request JSON:\n{}\n\nArtifact brief JSON:\n{}\n\nArtifact blueprint JSON:\n{}\n\nArtifact IR JSON:\n{}\n\nSelected skill guidance JSON:\n{}\n\nRetrieved exemplar JSON:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\n{}:\n{}\n\nInteraction contract JSON:\n{}\n\nEdit intent JSON:\n{}\n\nCurrent artifact context:\n{}\n\nCandidate metadata:\n{{\"candidateId\":\"{}\",\"candidateSeed\":{}}}\n\nCurrent candidate JSON:\n{}\n\nAcceptance judgment JSON:\n{}\n\nThe previous refinement payload was rejected.\nFailure:\n{}\n\nPrevious raw refinement output:\n{}\n{}\n\nRenderer-native authoring guidance:\n{}\n\nFailure-specific repair directives:\n{}\n\nRepair the refinement payload so it stays request-faithful, preserves working structure, and fully validates.\n\n{}",
                title,
                intent,
                request_json,
                brief_json,
                blueprint_json,
                artifact_ir_json,
                selected_skills_json,
                retrieved_exemplars_json,
                design_label,
                promoted_design_spine_json,
                scaffold_label,
                scaffold_contract_json,
                component_label,
                component_pack_contract_json,
                interaction_contract_json,
                edit_intent_json,
                refinement_json,
                candidate_id,
                candidate_seed,
                candidate_json,
                judge_json,
                failure,
                raw_output,
                scaffold_execution_block,
                renderer_guidance,
                failure_directives,
                schema_contract,
            )
        }
    ]))
}
