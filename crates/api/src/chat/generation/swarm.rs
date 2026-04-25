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

pub(super) fn chat_swarm_now_iso() -> String {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().to_string())
        .unwrap_or_else(|_| "0".to_string())
}

pub(super) fn chat_swarm_strategy_for_request(
    request: &ChatOutcomeArtifactRequest,
    execution_strategy: ChatExecutionStrategy,
) -> (&'static str, &'static str) {
    match (request.renderer, execution_strategy) {
        (ChatRendererKind::HtmlIframe, ChatExecutionStrategy::MicroSwarm) => {
            ("html_micro_swarm", "html_micro_v1")
        }
        (ChatRendererKind::HtmlIframe, _) => ("html_adaptive_work_graph", "html_adaptive_v1"),
        (ChatRendererKind::Markdown, ChatExecutionStrategy::MicroSwarm) => {
            ("markdown_micro_swarm", "markdown_micro_v1")
        }
        (ChatRendererKind::Markdown, _) => ("markdown_adaptive_work_graph", "markdown_adaptive_v1"),
        (ChatRendererKind::Svg, ChatExecutionStrategy::MicroSwarm) => {
            ("svg_micro_swarm", "svg_micro_v1")
        }
        (ChatRendererKind::Svg, _) => ("svg_adaptive_work_graph", "svg_adaptive_v1"),
        (ChatRendererKind::JsxSandbox, ChatExecutionStrategy::MicroSwarm) => {
            ("jsx_micro_swarm", "jsx_micro_v1")
        }
        (ChatRendererKind::JsxSandbox, _) => ("jsx_adaptive_work_graph", "jsx_adaptive_v1"),
        (ChatRendererKind::Mermaid, ChatExecutionStrategy::MicroSwarm) => {
            ("mermaid_micro_swarm", "mermaid_micro_v1")
        }
        (ChatRendererKind::Mermaid, _) => ("mermaid_adaptive_work_graph", "mermaid_adaptive_v1"),
        (ChatRendererKind::PdfEmbed, ChatExecutionStrategy::MicroSwarm) => {
            ("pdf_micro_swarm", "pdf_micro_v1")
        }
        (ChatRendererKind::PdfEmbed, _) => ("pdf_adaptive_work_graph", "pdf_adaptive_v1"),
        (ChatRendererKind::DownloadCard, ChatExecutionStrategy::MicroSwarm) => {
            ("download_bundle_micro_swarm", "download_bundle_micro_v1")
        }
        (ChatRendererKind::DownloadCard, _) => (
            "download_bundle_adaptive_work_graph",
            "download_bundle_adaptive_v1",
        ),
        (ChatRendererKind::BundleManifest, ChatExecutionStrategy::MicroSwarm) => {
            ("bundle_manifest_micro_swarm", "bundle_manifest_micro_v1")
        }
        (ChatRendererKind::BundleManifest, _) => (
            "bundle_manifest_adaptive_work_graph",
            "bundle_manifest_adaptive_v1",
        ),
        (ChatRendererKind::WorkspaceSurface, _) => {
            ("workspace_adaptive_work_graph", "workspace_adaptive_v1")
        }
    }
}

pub(super) fn default_chat_artifact_execution_strategy(
    request: &ChatOutcomeArtifactRequest,
) -> ChatExecutionStrategy {
    chat_execution_strategy_for_outcome(ChatOutcomeKind::Artifact, Some(request))
}

pub(super) fn chat_artifact_uses_swarm_execution(strategy: ChatExecutionStrategy) -> bool {
    matches!(
        strategy,
        ChatExecutionStrategy::MicroSwarm | ChatExecutionStrategy::AdaptiveWorkGraph
    )
}

pub(super) fn chat_swarm_soft_validation_error(error: &str) -> bool {
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

pub(super) fn validation_status_id(classification: ChatArtifactValidationStatus) -> &'static str {
    match classification {
        ChatArtifactValidationStatus::Pass => "pass",
        ChatArtifactValidationStatus::Repairable => "repairable",
        ChatArtifactValidationStatus::Blocked => "blocked",
    }
}

pub(super) fn default_generated_artifact_file_for_renderer(
    renderer: ChatRendererKind,
) -> ChatGeneratedArtifactFile {
    match renderer {
        ChatRendererKind::HtmlIframe => ChatGeneratedArtifactFile {
            path: "index.html".to_string(),
            mime: "text/html".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        ChatRendererKind::Markdown => ChatGeneratedArtifactFile {
            path: "artifact.md".to_string(),
            mime: "text/markdown".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        ChatRendererKind::JsxSandbox => ChatGeneratedArtifactFile {
            path: "artifact.jsx".to_string(),
            mime: "text/jsx".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        ChatRendererKind::Svg => ChatGeneratedArtifactFile {
            path: "artifact.svg".to_string(),
            mime: "image/svg+xml".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        ChatRendererKind::Mermaid => ChatGeneratedArtifactFile {
            path: "diagram.mermaid".to_string(),
            mime: "text/plain".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: false,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        ChatRendererKind::PdfEmbed => ChatGeneratedArtifactFile {
            path: "artifact.pdf".to_string(),
            mime: "application/pdf".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: true,
            downloadable: true,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        ChatRendererKind::DownloadCard => ChatGeneratedArtifactFile {
            path: "download.bin".to_string(),
            mime: "application/octet-stream".to_string(),
            role: ChatArtifactFileRole::Export,
            renderable: false,
            downloadable: true,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        ChatRendererKind::BundleManifest => ChatGeneratedArtifactFile {
            path: "bundle-manifest.json".to_string(),
            mime: "application/json".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: false,
            downloadable: true,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
        ChatRendererKind::WorkspaceSurface => ChatGeneratedArtifactFile {
            path: "artifact".to_string(),
            mime: "text/plain".to_string(),
            role: ChatArtifactFileRole::Primary,
            renderable: false,
            downloadable: false,
            encoding: Some(ChatGeneratedArtifactEncoding::Utf8),
            body: String::new(),
        },
    }
}

pub(super) fn update_swarm_work_item_status(
    swarm_plan: &mut ChatArtifactSwarmPlan,
    work_item_id: &str,
    status: ChatArtifactWorkItemStatus,
) {
    if let Some(work_item) = swarm_plan
        .work_items
        .iter_mut()
        .find(|item| item.id == work_item_id)
    {
        work_item.status = status;
    }
}

pub(super) fn chat_swarm_execution_summary(
    swarm_plan: &ChatArtifactSwarmPlan,
    current_stage: &str,
    active_worker_role: Option<ChatArtifactWorkerRole>,
    verification_status: &str,
) -> ChatArtifactSwarmExecutionSummary {
    let completed_work_items = swarm_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                ChatArtifactWorkItemStatus::Succeeded | ChatArtifactWorkItemStatus::Skipped
            )
        })
        .count();
    let failed_work_items = swarm_plan
        .work_items
        .iter()
        .filter(|item| {
            matches!(
                item.status,
                ChatArtifactWorkItemStatus::Blocked
                    | ChatArtifactWorkItemStatus::Failed
                    | ChatArtifactWorkItemStatus::Rejected
            )
        })
        .count();

    ChatArtifactSwarmExecutionSummary {
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

pub(super) fn section_region_id(section: &ChatArtifactSectionPlan, index: usize) -> String {
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
