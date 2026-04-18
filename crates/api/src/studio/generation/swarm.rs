use super::*;
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn execution_stage_for_swarm_current_stage(current_stage: &str) -> ExecutionStage {
    match current_stage.trim().to_ascii_lowercase().as_str() {
        "intake" | "requirements" | "specification" | "planner" | "plan" => ExecutionStage::Plan,
        "routing" | "dispatch" => ExecutionStage::Dispatch,
        "swarm_execution" | "work" => ExecutionStage::Work,
        "materialization" | "execution" | "repair" | "mutate" => ExecutionStage::Mutate,
        "merge" => ExecutionStage::Merge,
        "verification" | "verify" => ExecutionStage::Verify,
        "presentation" | "reply" | "finalize" | "final" => ExecutionStage::Finalize,
        _ => ExecutionStage::Work,
    }
}

pub(super) fn studio_swarm_now_iso() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

pub(super) fn studio_swarm_strategy_for_request(
    request: &StudioOutcomeArtifactRequest,
    execution_strategy: StudioExecutionStrategy,
) -> (&'static str, &'static str) {
    match (request.renderer, execution_strategy) {
        (StudioRendererKind::HtmlIframe, StudioExecutionStrategy::MicroSwarm) => {
            ("html_micro_swarm", "html_micro_v1")
        }
        (StudioRendererKind::HtmlIframe, _) => ("html_adaptive_work_graph", "html_adaptive_v1"),
        (StudioRendererKind::Markdown, StudioExecutionStrategy::MicroSwarm) => {
            ("markdown_micro_swarm", "markdown_micro_v1")
        }
        (StudioRendererKind::Markdown, _) => {
            ("markdown_adaptive_work_graph", "markdown_adaptive_v1")
        }
        (StudioRendererKind::Svg, StudioExecutionStrategy::MicroSwarm) => {
            ("svg_micro_swarm", "svg_micro_v1")
        }
        (StudioRendererKind::Svg, _) => ("svg_adaptive_work_graph", "svg_adaptive_v1"),
        (StudioRendererKind::JsxSandbox, StudioExecutionStrategy::MicroSwarm) => {
            ("jsx_micro_swarm", "jsx_micro_v1")
        }
        (StudioRendererKind::JsxSandbox, _) => ("jsx_adaptive_work_graph", "jsx_adaptive_v1"),
        (StudioRendererKind::Mermaid, StudioExecutionStrategy::MicroSwarm) => {
            ("mermaid_micro_swarm", "mermaid_micro_v1")
        }
        (StudioRendererKind::Mermaid, _) => ("mermaid_adaptive_work_graph", "mermaid_adaptive_v1"),
        (StudioRendererKind::PdfEmbed, StudioExecutionStrategy::MicroSwarm) => {
            ("pdf_micro_swarm", "pdf_micro_v1")
        }
        (StudioRendererKind::PdfEmbed, _) => ("pdf_adaptive_work_graph", "pdf_adaptive_v1"),
        (StudioRendererKind::DownloadCard, StudioExecutionStrategy::MicroSwarm) => {
            ("download_bundle_micro_swarm", "download_bundle_micro_v1")
        }
        (StudioRendererKind::DownloadCard, _) => (
            "download_bundle_adaptive_work_graph",
            "download_bundle_adaptive_v1",
        ),
        (StudioRendererKind::BundleManifest, StudioExecutionStrategy::MicroSwarm) => {
            ("bundle_manifest_micro_swarm", "bundle_manifest_micro_v1")
        }
        (StudioRendererKind::BundleManifest, _) => (
            "bundle_manifest_adaptive_work_graph",
            "bundle_manifest_adaptive_v1",
        ),
        (StudioRendererKind::WorkspaceSurface, _) => {
            ("workspace_adaptive_work_graph", "workspace_adaptive_v1")
        }
    }
}

pub(super) fn default_studio_artifact_execution_strategy(
    request: &StudioOutcomeArtifactRequest,
) -> StudioExecutionStrategy {
    studio_execution_strategy_for_outcome(StudioOutcomeKind::Artifact, Some(request))
}

pub(super) fn studio_artifact_uses_swarm_execution(strategy: StudioExecutionStrategy) -> bool {
    matches!(
        strategy,
        StudioExecutionStrategy::MicroSwarm | StudioExecutionStrategy::AdaptiveWorkGraph
    )
}

pub(super) fn studio_swarm_soft_validation_error(error: &str) -> bool {
    [
        "HTML iframe artifacts that include chart or diagram SVG regions must render real SVG marks or labels on first paint.",
        "HTML iframe artifacts that include chart or diagram SVG regions must include visible labels, legends, or aria labels on first paint.",
        "HTML iframe artifacts that include chart or diagram containers must render visible chart content on first paint.",
        "HTML iframe artifacts must contain at least three sectioning elements with first-paint content.",
        "Interactive HTML iframe artifacts must update on-page state or shared detail, not only scroll, jump, or log.",
    ]
    .iter()
    .any(|needle| error.contains(needle))
}

pub(super) fn validation_status_id(classification: StudioArtifactValidationStatus) -> &'static str {
    match classification {
        StudioArtifactValidationStatus::Pass => "pass",
        StudioArtifactValidationStatus::Repairable => "repairable",
        StudioArtifactValidationStatus::Blocked => "blocked",
    }
}

pub(super) fn default_generated_artifact_file_for_renderer(
    renderer: StudioRendererKind,
) -> StudioGeneratedArtifactFile {
    match renderer {
        StudioRendererKind::HtmlIframe => StudioGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        StudioRendererKind::Markdown => StudioGeneratedArtifactFile {
            path: "artifact.md".to_string(),
            mime: "text/markdown".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        StudioRendererKind::JsxSandbox => StudioGeneratedArtifactFile {
            path: "artifact.jsx".to_string(),
            mime: "text/jsx".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        StudioRendererKind::Svg => StudioGeneratedArtifactFile {
            path: "artifact.svg".to_string(),
            mime: "image/svg+xml".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        StudioRendererKind::Mermaid => StudioGeneratedArtifactFile {
            path: "diagram.mermaid".to_string(),
            mime: "text/plain".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        StudioRendererKind::PdfEmbed => StudioGeneratedArtifactFile {
            path: "artifact.pdf".to_string(),
            mime: "application/pdf".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        StudioRendererKind::DownloadCard => StudioGeneratedArtifactFile {
            path: "download.bin".to_string(),
            mime: "application/octet-stream".to_string(),
            role: StudioArtifactFileRole::Export,
            renderable: false,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        StudioRendererKind::BundleManifest => StudioGeneratedArtifactFile {
            path: "bundle-manifest.json".to_string(),
            mime: "application/json".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: false,
            downloadable: true,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        StudioRendererKind::WorkspaceSurface => StudioGeneratedArtifactFile {
            path: "artifact".to_string(),
            mime: "text/plain".to_string(),
            role: StudioArtifactFileRole::Primary,
            renderable: false,
            downloadable: false,
            encoding: Some(StudioGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
    }
}

pub(super) fn update_swarm_work_item_status(
    swarm_plan: &mut StudioArtifactSwarmPlan,
    work_item_id: &str,
    status: StudioArtifactWorkItemStatus,
) {
    if let Some(work_item) = swarm_plan
        .work_items
        .iter_mut()
        .find(|item| item.id == work_item_id)
    {
        work_item.status = status;
    }
}

pub(super) fn studio_swarm_execution_summary(
    swarm_plan: &StudioArtifactSwarmPlan,
    current_stage: &str,
    active_worker_role: Option<StudioArtifactWorkerRole>,
    verification_status: &str,
) -> StudioArtifactSwarmExecutionSummary {
    let completed_work_items = swarm_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                StudioArtifactWorkItemStatus::Succeeded | StudioArtifactWorkItemStatus::Skipped
            )
        })
        .count();
    let failed_work_items = swarm_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                StudioArtifactWorkItemStatus::Blocked
                    | StudioArtifactWorkItemStatus::Failed
                    | StudioArtifactWorkItemStatus::Rejected
            )
        })
        .count();

    StudioArtifactSwarmExecutionSummary {
        enabled: true,
        current_stage: current_stage.to_string(),
        execution_stage: Some(execution_stage_for_swarm_current_stage(current_stage)),
        active_worker_role,
        total_work_items: swarm_plan.work_items.len(),
        completed_work_items,
        failed_work_items,
        verification_status: verification_status.to_string(),
        strategy: swarm_plan.strategy.clone(),
        execution_domain: swarm_plan.execution_domain.clone(),
        adapter_label: swarm_plan.adapter_label.clone(),
        parallelism_mode: swarm_plan.parallelism_mode.clone(),
    }
}

pub(super) fn section_region_id(section: &StudioArtifactSectionPlan, index: usize) -> String {
    let raw = if section.id.trim().is_empty() {
        format!("section-{}", index + 1)
    } else {
        section.id.clone()
    };
    raw.chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' => ch,
            'A'..='Z' => ch.to_ascii_lowercase(),
            _ => '-',
        })
        .collect::<String>()
        .split('-')
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-")
}

pub(super) fn push_unique_focus_strings(
    target: &mut Vec<String>,
    source: impl IntoIterator<Item = String>,
    max_items: usize,
) {
    for item in source {
        let trimmed = item.trim();
        if trimmed.is_empty() || target.iter().any(|existing| existing == trimmed) {
            continue;
        }
        target.push(trimmed.to_string());
        if target.len() >= max_items {
            break;
        }
    }
}
