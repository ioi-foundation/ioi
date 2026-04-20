use super::content_session::renderer_kind_id;
use super::presentation::truncate_preview;
use super::*;
use ioi_api::execution::ExecutionLivePreview;
use ioi_api::studio::{
    StudioArtifactFileRef, StudioArtifactOperatorPhase, StudioArtifactOperatorPreview,
    StudioArtifactOperatorRun, StudioArtifactOperatorRunMode, StudioArtifactOperatorRunStatus,
    StudioArtifactOperatorStep, StudioArtifactSourcePack, StudioArtifactSourceReference,
    StudioArtifactVerificationOutcome, StudioArtifactVerificationRef,
};
use ioi_types::app::StudioExecutionStrategy;
use uuid::Uuid;

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or_default()
}

fn normalize_origin_prompt_event_id(value: Option<&str>) -> String {
    value
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or_default()
        .to_string()
}

fn basename(path: &str) -> String {
    let trimmed = path.trim().trim_end_matches(['/', '\\']);
    if trimmed.is_empty() {
        return "artifact".to_string();
    }
    trimmed
        .rsplit(['/', '\\'])
        .next()
        .filter(|value| !value.is_empty())
        .unwrap_or(trimmed)
        .to_string()
}

fn session_is_presentable(session: &StudioArtifactSession) -> bool {
    let verification_status =
        format!("{:?}", session.artifact_manifest.verification.status).to_ascii_lowercase();
    let lifecycle_state = format!(
        "{:?}",
        session.artifact_manifest.verification.lifecycle_state
    )
    .to_ascii_lowercase();

    if matches!(verification_status.as_str(), "blocked" | "failed")
        || matches!(lifecycle_state.as_str(), "blocked" | "failed")
    {
        return true;
    }

    if matches!(verification_status.as_str(), "ready" | "partial")
        || session.status.trim().eq_ignore_ascii_case("ready")
    {
        return !session.artifact_manifest.files.is_empty();
    }

    false
}

fn operator_status_for_session(
    session: &StudioArtifactSession,
    build_session: Option<&BuildArtifactSession>,
) -> StudioArtifactOperatorRunStatus {
    if session.lifecycle_state == StudioArtifactLifecycleState::Failed {
        return StudioArtifactOperatorRunStatus::Failed;
    }
    if session.lifecycle_state == StudioArtifactLifecycleState::Blocked {
        return StudioArtifactOperatorRunStatus::Blocked;
    }
    if build_session.is_some_and(|candidate| {
        candidate.build_status.eq_ignore_ascii_case("failed")
            || candidate.verification_status.eq_ignore_ascii_case("failed")
    }) {
        return StudioArtifactOperatorRunStatus::Blocked;
    }
    if session_is_presentable(session) {
        return StudioArtifactOperatorRunStatus::Complete;
    }
    StudioArtifactOperatorRunStatus::Active
}

fn step_status_is_settled(status: StudioArtifactOperatorRunStatus) -> bool {
    matches!(
        status,
        StudioArtifactOperatorRunStatus::Complete
            | StudioArtifactOperatorRunStatus::Blocked
            | StudioArtifactOperatorRunStatus::Failed
    )
}

fn phase_rank(phase: StudioArtifactOperatorPhase, attempt: u32) -> u32 {
    let base = match phase {
        StudioArtifactOperatorPhase::UnderstandRequest => 100,
        StudioArtifactOperatorPhase::RouteArtifact => 150,
        StudioArtifactOperatorPhase::ReopenArtifactContext => 180,
        StudioArtifactOperatorPhase::SearchSources => 250,
        StudioArtifactOperatorPhase::ReadSources => 300,
        StudioArtifactOperatorPhase::AuthorArtifact => 500,
        StudioArtifactOperatorPhase::RepairArtifact => 620,
        StudioArtifactOperatorPhase::InspectArtifact => 700,
        StudioArtifactOperatorPhase::VerifyArtifact => 800,
        StudioArtifactOperatorPhase::PresentArtifact => 900,
        StudioArtifactOperatorPhase::Other => 1_000,
    };
    base + attempt
}

fn phase_slug(phase: StudioArtifactOperatorPhase) -> &'static str {
    match phase {
        StudioArtifactOperatorPhase::UnderstandRequest => "understand_request",
        StudioArtifactOperatorPhase::RouteArtifact => "route_artifact",
        StudioArtifactOperatorPhase::ReopenArtifactContext => "reopen_artifact_context",
        StudioArtifactOperatorPhase::SearchSources => "search_sources",
        StudioArtifactOperatorPhase::ReadSources => "read_sources",
        StudioArtifactOperatorPhase::AuthorArtifact => "author_artifact",
        StudioArtifactOperatorPhase::InspectArtifact => "inspect_artifact",
        StudioArtifactOperatorPhase::VerifyArtifact => "verify_artifact",
        StudioArtifactOperatorPhase::RepairArtifact => "repair_artifact",
        StudioArtifactOperatorPhase::PresentArtifact => "present_artifact",
        StudioArtifactOperatorPhase::Other => "other",
    }
}

fn build_step_id(run_id: &str, phase: StudioArtifactOperatorPhase, attempt: u32) -> String {
    format!("{run_id}:{}:{attempt}", phase_slug(phase))
}

fn execution_strategy_id(strategy: StudioExecutionStrategy) -> &'static str {
    match strategy {
        StudioExecutionStrategy::SinglePass => "single_pass",
        StudioExecutionStrategy::DirectAuthor => "direct_author",
        StudioExecutionStrategy::PlanExecute => "plan_execute",
        StudioExecutionStrategy::MicroSwarm => "micro_swarm",
        StudioExecutionStrategy::AdaptiveWorkGraph => "adaptive_work_graph",
    }
}

fn engine_summary_for_session(session: &StudioArtifactSession) -> String {
    format!(
        "{} via {}",
        renderer_kind_id(session.artifact_manifest.renderer),
        execution_strategy_id(session.outcome_request.execution_strategy),
    )
}

fn latest_live_preview(session: &StudioArtifactSession) -> Option<ExecutionLivePreview> {
    session
        .materialization
        .execution_envelope
        .as_ref()
        .and_then(|envelope| {
            envelope
                .live_previews
                .iter()
                .filter(|preview| !preview.content.trim().is_empty())
                .max_by(|left, right| {
                    left.updated_at
                        .cmp(&right.updated_at)
                        .then_with(|| left.id.cmp(&right.id))
                })
        })
        .cloned()
}

fn live_author_preview(
    session: &StudioArtifactSession,
    origin_prompt_event_id: &str,
) -> Option<StudioArtifactOperatorPreview> {
    let preview = latest_live_preview(session)?;
    Some(StudioArtifactOperatorPreview {
        origin_prompt_event_id: origin_prompt_event_id.to_string(),
        label: preview.label,
        content: preview.content,
        status: preview.status,
        kind: Some(format!("{:?}", preview.kind).to_ascii_lowercase()),
        language: preview.language,
        is_final: preview.is_final,
    })
}

fn primary_manifest_file(session: &StudioArtifactSession) -> Option<&StudioArtifactManifestFile> {
    session
        .artifact_manifest
        .files
        .iter()
        .find(|file| file.path == session.artifact_manifest.primary_tab)
        .or_else(|| {
            session
                .artifact_manifest
                .files
                .iter()
                .find(|file| file.renderable)
        })
        .or_else(|| session.artifact_manifest.files.first())
}

fn build_file_ref(
    file: &StudioArtifactManifestFile,
    origin_prompt_event_id: &str,
) -> StudioArtifactFileRef {
    StudioArtifactFileRef {
        file_id: file
            .artifact_id
            .clone()
            .unwrap_or_else(|| format!("file:{}", file.path)),
        origin_prompt_event_id: origin_prompt_event_id.to_string(),
        path: file.path.clone(),
        role: file.role,
        mime: file.mime.clone(),
        summary: if file.renderable {
            format!("Renderable {} file.", basename(&file.path))
        } else {
            format!("Supporting {} file.", basename(&file.path))
        },
    }
}

fn final_artifacts_for_session(
    session: &StudioArtifactSession,
    origin_prompt_event_id: &str,
) -> Vec<StudioArtifactFileRef> {
    session
        .artifact_manifest
        .files
        .iter()
        .map(|file| build_file_ref(file, origin_prompt_event_id))
        .collect()
}

fn inspect_preview_for_session(
    session: &StudioArtifactSession,
    origin_prompt_event_id: &str,
) -> Option<(
    String,
    StudioArtifactOperatorPreview,
    Vec<StudioArtifactFileRef>,
)> {
    if let Some(write) = session.materialization.file_writes.first() {
        let preview = write.content_preview.as_deref().unwrap_or_default().trim();
        if preview.is_empty() {
            return None;
        }
        let file = session
            .artifact_manifest
            .files
            .iter()
            .find(|candidate| candidate.path == write.path);
        let file_refs = file
            .map(|candidate| vec![build_file_ref(candidate, origin_prompt_event_id)])
            .unwrap_or_default();
        return Some((
            write.path.clone(),
            StudioArtifactOperatorPreview {
                origin_prompt_event_id: origin_prompt_event_id.to_string(),
                label: basename(&write.path),
                content: preview.to_string(),
                status: "complete".to_string(),
                kind: Some("readback".to_string()),
                language: None,
                is_final: true,
            },
            file_refs,
        ));
    }

    let file = primary_manifest_file(session)?;
    Some((
        file.path.clone(),
        StudioArtifactOperatorPreview {
            origin_prompt_event_id: origin_prompt_event_id.to_string(),
            label: basename(&file.path),
            content: truncate_preview(&session.verified_reply.summary.trim().to_string()),
            status: "complete".to_string(),
            kind: Some("manifest".to_string()),
            language: None,
            is_final: true,
        },
        vec![build_file_ref(file, origin_prompt_event_id)],
    ))
}

fn source_pack_for_session(
    session: &StudioArtifactSession,
    origin_prompt_event_id: &str,
) -> StudioArtifactSourcePack {
    let mut items = Vec::new();

    for source in &session.materialization.retrieved_sources {
        let mut source = source.clone();
        if source.origin_prompt_event_id.trim().is_empty() {
            source.origin_prompt_event_id = origin_prompt_event_id.to_string();
        }
        items.push(source);
    }

    if items.is_empty() {
        if let Some(brief) = session.materialization.artifact_brief.as_ref() {
            for (index, anchor) in brief.factual_anchors.iter().enumerate() {
                let anchor = anchor.trim();
                if anchor.is_empty() {
                    continue;
                }
                items.push(StudioArtifactSourceReference {
                    source_id: format!("anchor:{index}"),
                    origin_prompt_event_id: origin_prompt_event_id.to_string(),
                    title: anchor.to_string(),
                    url: None,
                    domain: None,
                    excerpt: Some(anchor.to_string()),
                    retrieved_at_ms: None,
                    freshness: Some("brief_anchor".to_string()),
                    reason: "Required factual anchor from the artifact brief.".to_string(),
                });
            }
            for (index, hint) in brief.reference_hints.iter().enumerate() {
                let hint = hint.trim();
                if hint.is_empty() {
                    continue;
                }
                items.push(StudioArtifactSourceReference {
                    source_id: format!("hint:{index}"),
                    origin_prompt_event_id: origin_prompt_event_id.to_string(),
                    title: hint.to_string(),
                    url: None,
                    domain: None,
                    excerpt: None,
                    retrieved_at_ms: None,
                    freshness: Some("reference_hint".to_string()),
                    reason: "Reference hint captured while shaping the artifact brief.".to_string(),
                });
            }
        }
    }

    for exemplar in &session.materialization.retrieved_exemplars {
        items.push(StudioArtifactSourceReference {
            source_id: format!("exemplar:{}", exemplar.record_id),
            origin_prompt_event_id: origin_prompt_event_id.to_string(),
            title: exemplar.title.clone(),
            url: None,
            domain: None,
            excerpt: Some(exemplar.summary.clone()),
            retrieved_at_ms: None,
            freshness: Some("artifact_exemplar".to_string()),
            reason: exemplar.quality_rationale.clone(),
        });
    }

    let summary = if items.is_empty() {
        String::new()
    } else {
        format!(
            "Grounded this artifact run with {} source item(s).",
            items.len()
        )
    };

    StudioArtifactSourcePack { summary, items }
}

fn prompt_requires_source_pack(
    session: &StudioArtifactSession,
    source_pack: &StudioArtifactSourcePack,
) -> bool {
    if !source_pack.items.is_empty() {
        return true;
    }

    let prompt = session.outcome_request.raw_prompt.to_ascii_lowercase();
    [
        "explainer",
        "guide",
        "overview",
        "primer",
        "current",
        "latest",
        "source-backed",
        "sources",
    ]
    .iter()
    .any(|keyword| prompt.contains(keyword))
}

fn build_source_activity_preview(source_pack: &StudioArtifactSourcePack) -> Option<String> {
    let lines = source_pack
        .items
        .iter()
        .take(6)
        .map(|item| {
            let title = item.title.trim();
            let domain = item.domain.as_deref().unwrap_or_default().trim();
            if title.is_empty() {
                domain.to_string()
            } else if domain.is_empty() {
                title.to_string()
            } else {
                format!("{title} - {domain}")
            }
        })
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    if lines.is_empty() {
        None
    } else {
        Some(lines.join("\n"))
    }
}

fn verification_refs_and_outcome(
    session: &StudioArtifactSession,
    origin_prompt_event_id: &str,
) -> (
    Vec<StudioArtifactVerificationRef>,
    Option<StudioArtifactVerificationOutcome>,
) {
    let Some(render_evaluation) = session.materialization.render_evaluation.as_ref() else {
        if session.lifecycle_state == StudioArtifactLifecycleState::Blocked
            || session.lifecycle_state == StudioArtifactLifecycleState::Failed
        {
            return (
                Vec::new(),
                Some(StudioArtifactVerificationOutcome {
                    status: StudioArtifactOperatorRunStatus::Blocked,
                    summary: session.artifact_manifest.verification.summary.clone(),
                    required_obligation_count: 0,
                    cleared_obligation_count: 0,
                    failed_obligation_count: 1,
                }),
            );
        }
        return (Vec::new(), None);
    };

    let mut refs = Vec::new();
    for obligation in &render_evaluation.acceptance_obligations {
        refs.push(StudioArtifactVerificationRef {
            verification_id: obligation.obligation_id.clone(),
            origin_prompt_event_id: origin_prompt_event_id.to_string(),
            family: obligation.family.clone(),
            status: format!("{:?}", obligation.status).to_ascii_lowercase(),
            summary: obligation.summary.clone(),
            detail: obligation.detail.clone(),
            selector: None,
        });
    }
    for witness in &render_evaluation.execution_witnesses {
        refs.push(StudioArtifactVerificationRef {
            verification_id: witness.witness_id.clone(),
            origin_prompt_event_id: origin_prompt_event_id.to_string(),
            family: witness.action_kind.clone(),
            status: format!("{:?}", witness.status).to_ascii_lowercase(),
            summary: witness.summary.clone(),
            detail: witness.detail.clone(),
            selector: witness.selector.clone(),
        });
    }

    let status = if render_evaluation.blocked_by_policy() {
        StudioArtifactOperatorRunStatus::Blocked
    } else {
        StudioArtifactOperatorRunStatus::Complete
    };

    (
        refs,
        Some(StudioArtifactVerificationOutcome {
            status,
            summary: render_evaluation.summary.clone(),
            required_obligation_count: render_evaluation.required_obligation_count(),
            cleared_obligation_count: render_evaluation.cleared_required_obligation_count(),
            failed_obligation_count: render_evaluation.failed_required_obligation_count(),
        }),
    )
}

fn upsert_step(steps: &mut Vec<StudioArtifactOperatorStep>, next: StudioArtifactOperatorStep) {
    if let Some(existing) = steps.iter_mut().find(|step| step.step_id == next.step_id) {
        *existing = next;
    } else {
        steps.push(next);
    }
}

fn build_base_step(
    run_id: &str,
    origin_prompt_event_id: &str,
    phase: StudioArtifactOperatorPhase,
    label: impl Into<String>,
    detail: impl Into<String>,
    started_at_ms: u64,
) -> StudioArtifactOperatorStep {
    StudioArtifactOperatorStep {
        step_id: build_step_id(run_id, phase, 0),
        origin_prompt_event_id: origin_prompt_event_id.to_string(),
        phase,
        engine: "studio_operator".to_string(),
        status: StudioArtifactOperatorRunStatus::Complete,
        label: label.into(),
        detail: detail.into(),
        started_at_ms,
        finished_at_ms: Some(started_at_ms),
        preview: None,
        file_refs: Vec::new(),
        source_refs: Vec::new(),
        verification_refs: Vec::new(),
        attempt: 0,
    }
}

fn hydrate_typed_steps(
    steps: &mut Vec<StudioArtifactOperatorStep>,
    session: &StudioArtifactSession,
    origin_prompt_event_id: &str,
    source_pack: &StudioArtifactSourcePack,
    final_artifacts: &[StudioArtifactFileRef],
    verification_refs: &[StudioArtifactVerificationRef],
) {
    let live_preview = live_author_preview(session, origin_prompt_event_id);
    for step in steps.iter_mut() {
        if step.origin_prompt_event_id.is_empty() {
            step.origin_prompt_event_id = origin_prompt_event_id.to_string();
        }
        match step.phase {
            StudioArtifactOperatorPhase::SearchSources
            | StudioArtifactOperatorPhase::ReadSources => {
                if step.source_refs.is_empty() {
                    step.source_refs = source_pack.items.clone();
                }
            }
            StudioArtifactOperatorPhase::AuthorArtifact => {
                if step.preview.is_none() {
                    step.preview = live_preview.clone();
                }
                if step.source_refs.is_empty() {
                    step.source_refs = source_pack.items.clone();
                }
            }
            StudioArtifactOperatorPhase::InspectArtifact => {
                if step.file_refs.is_empty() && !final_artifacts.is_empty() {
                    step.file_refs = final_artifacts.to_vec();
                }
            }
            StudioArtifactOperatorPhase::VerifyArtifact => {
                if step.file_refs.is_empty() && !final_artifacts.is_empty() {
                    step.file_refs = final_artifacts.to_vec();
                }
                if step.source_refs.is_empty() {
                    step.source_refs = source_pack.items.clone();
                }
                if step.verification_refs.is_empty() && !verification_refs.is_empty() {
                    step.verification_refs = verification_refs.to_vec();
                }
            }
            StudioArtifactOperatorPhase::PresentArtifact => {
                if step.file_refs.is_empty() && !final_artifacts.is_empty() {
                    step.file_refs = final_artifacts.to_vec();
                }
            }
            _ => {}
        }
    }
}

fn base_steps_for_new_run(
    session: &StudioArtifactSession,
    run_id: &str,
    origin_prompt_event_id: &str,
    mode: StudioArtifactOperatorRunMode,
    started_at_ms: u64,
) -> Vec<StudioArtifactOperatorStep> {
    let mut steps = Vec::new();
    match mode {
        StudioArtifactOperatorRunMode::Create => {
            steps.push(build_base_step(
                run_id,
                origin_prompt_event_id,
                StudioArtifactOperatorPhase::UnderstandRequest,
                "Understand request",
                "Studio captured the request and established the active artifact context.",
                started_at_ms,
            ));
            steps.push(build_base_step(
                run_id,
                origin_prompt_event_id,
                StudioArtifactOperatorPhase::RouteArtifact,
                "Route to artifact",
                format!(
                    "Studio committed the request to the {} artifact route.",
                    renderer_kind_id(session.artifact_manifest.renderer)
                ),
                started_at_ms.saturating_add(1),
            ));
        }
        StudioArtifactOperatorRunMode::Edit => {
            steps.push(build_base_step(
                run_id,
                origin_prompt_event_id,
                StudioArtifactOperatorPhase::ReopenArtifactContext,
                "Reopen artifact context",
                "Studio reopened the current artifact session before applying the follow-up edit.",
                started_at_ms,
            ));
            if let Some((path, preview, file_refs)) =
                inspect_preview_for_session(session, origin_prompt_event_id)
            {
                steps.push(StudioArtifactOperatorStep {
                    step_id: build_step_id(run_id, StudioArtifactOperatorPhase::InspectArtifact, 0),
                    origin_prompt_event_id: origin_prompt_event_id.to_string(),
                    phase: StudioArtifactOperatorPhase::InspectArtifact,
                    engine: "artifact_context".to_string(),
                    status: StudioArtifactOperatorRunStatus::Complete,
                    label: format!("Inspect {}", basename(&path)),
                    detail: format!(
                        "Studio inspected the current artifact before continuing the edit."
                    ),
                    started_at_ms: started_at_ms.saturating_add(1),
                    finished_at_ms: Some(started_at_ms.saturating_add(1)),
                    preview: Some(preview),
                    file_refs,
                    source_refs: Vec::new(),
                    verification_refs: Vec::new(),
                    attempt: 0,
                });
            }
        }
    }
    steps
}

pub(super) fn start_operator_run_for_session(
    session: &mut StudioArtifactSession,
    origin_prompt_event_id: Option<&str>,
    mode: StudioArtifactOperatorRunMode,
) {
    if let Some(previous) = session.active_operator_run.take() {
        session.operator_run_history.push(previous);
    }

    let origin_prompt_event_id = normalize_origin_prompt_event_id(
        origin_prompt_event_id.or(session.origin_prompt_event_id.as_deref()),
    );
    if !origin_prompt_event_id.is_empty() {
        session.origin_prompt_event_id = Some(origin_prompt_event_id.clone());
    }
    let started_at_ms = now_ms();
    let run_id = Uuid::new_v4().to_string();
    let run = StudioArtifactOperatorRun {
        run_id: run_id.clone(),
        origin_prompt_event_id: origin_prompt_event_id.clone(),
        artifact_session_id: session.session_id.clone(),
        mode,
        status: StudioArtifactOperatorRunStatus::Active,
        started_at_ms,
        finished_at_ms: None,
        engine_summary: engine_summary_for_session(session),
        source_pack: StudioArtifactSourcePack::default(),
        steps: base_steps_for_new_run(
            session,
            &run_id,
            &origin_prompt_event_id,
            mode,
            started_at_ms,
        ),
        final_artifacts: Vec::new(),
        verification_outcome: None,
        repair_count: 0,
    };
    session.materialization.operator_steps = run.steps.clone();
    session.active_operator_run = Some(run);
}

pub(super) fn refresh_active_operator_run_from_session(
    session: &mut StudioArtifactSession,
    build_session: Option<&BuildArtifactSession>,
) {
    let Some(mut run) = session.active_operator_run.take() else {
        return;
    };

    let origin_prompt_event_id =
        normalize_origin_prompt_event_id(session.origin_prompt_event_id.as_deref());
    run.origin_prompt_event_id = origin_prompt_event_id.clone();
    run.artifact_session_id = session.session_id.clone();
    run.engine_summary = engine_summary_for_session(session);
    run.source_pack = source_pack_for_session(session, &origin_prompt_event_id);
    run.final_artifacts = final_artifacts_for_session(session, &origin_prompt_event_id);
    let (verification_refs, verification_outcome) =
        verification_refs_and_outcome(session, &origin_prompt_event_id);

    let mut steps = if !session.materialization.operator_steps.is_empty() {
        session
            .materialization
            .operator_steps
            .iter()
            .filter(|step| {
                origin_prompt_event_id.is_empty()
                    || step.origin_prompt_event_id.is_empty()
                    || step.origin_prompt_event_id == origin_prompt_event_id
            })
            .cloned()
            .collect::<Vec<_>>()
    } else {
        run.steps.clone()
    };
    steps.retain(|step| step.phase != StudioArtifactOperatorPhase::PresentArtifact);
    hydrate_typed_steps(
        &mut steps,
        session,
        &origin_prompt_event_id,
        &run.source_pack,
        &run.final_artifacts,
        &verification_refs,
    );

    if prompt_requires_source_pack(session, &run.source_pack) {
        upsert_step(
            &mut steps,
            StudioArtifactOperatorStep {
                step_id: build_step_id(&run.run_id, StudioArtifactOperatorPhase::SearchSources, 0),
                origin_prompt_event_id: origin_prompt_event_id.clone(),
                phase: StudioArtifactOperatorPhase::SearchSources,
                engine: "source_pack".to_string(),
                status: if run.source_pack.items.is_empty() {
                    StudioArtifactOperatorRunStatus::Active
                } else {
                    StudioArtifactOperatorRunStatus::Complete
                },
                label: "Search for context".to_string(),
                detail: if run.source_pack.items.is_empty() {
                    "Studio is gathering the factual/source context this artifact depends on."
                        .to_string()
                } else {
                    run.source_pack.summary.clone()
                },
                started_at_ms: run.started_at_ms.saturating_add(2),
                finished_at_ms: (!run.source_pack.items.is_empty())
                    .then_some(run.started_at_ms.saturating_add(2)),
                preview: build_source_activity_preview(&run.source_pack).map(|content| {
                    StudioArtifactOperatorPreview {
                        origin_prompt_event_id: origin_prompt_event_id.clone(),
                        label: "Source pack".to_string(),
                        content,
                        status: "complete".to_string(),
                        kind: Some("source_pack".to_string()),
                        language: None,
                        is_final: true,
                    }
                }),
                file_refs: Vec::new(),
                source_refs: run.source_pack.items.clone(),
                verification_refs: Vec::new(),
                attempt: 0,
            },
        );
        if !run.source_pack.items.is_empty() {
            upsert_step(
                &mut steps,
                StudioArtifactOperatorStep {
                    step_id: build_step_id(
                        &run.run_id,
                        StudioArtifactOperatorPhase::ReadSources,
                        0,
                    ),
                    origin_prompt_event_id: origin_prompt_event_id.clone(),
                    phase: StudioArtifactOperatorPhase::ReadSources,
                    engine: "source_pack".to_string(),
                    status: StudioArtifactOperatorRunStatus::Complete,
                    label: "Read sources".to_string(),
                    detail:
                        "Studio selected the source excerpts that will stay attached to authoring, verification, and repair."
                            .to_string(),
                    started_at_ms: run.started_at_ms.saturating_add(3),
                    finished_at_ms: Some(run.started_at_ms.saturating_add(3)),
                    preview: build_source_activity_preview(&run.source_pack).map(|content| {
                        StudioArtifactOperatorPreview {
                            origin_prompt_event_id: origin_prompt_event_id.clone(),
                            label: "Selected sources".to_string(),
                            content,
                            status: "complete".to_string(),
                            kind: Some("source_excerpt".to_string()),
                            language: None,
                            is_final: true,
                        }
                    }),
                    file_refs: Vec::new(),
                    source_refs: run.source_pack.items.clone(),
                    verification_refs: Vec::new(),
                    attempt: 0,
                },
            );
        }
    }

    if build_session.is_none()
        && !steps.iter().any(|step| {
            step.phase == StudioArtifactOperatorPhase::AuthorArtifact && step.attempt >= 1
        })
    {
        let author_status = if session.lifecycle_state == StudioArtifactLifecycleState::Blocked
            || session.lifecycle_state == StudioArtifactLifecycleState::Failed
        {
            StudioArtifactOperatorRunStatus::Blocked
        } else if session.artifact_manifest.files.is_empty() {
            StudioArtifactOperatorRunStatus::Active
        } else {
            StudioArtifactOperatorRunStatus::Complete
        };
        let target = primary_manifest_file(session)
            .map(|file| basename(&file.path))
            .unwrap_or_else(|| "artifact".to_string());
        upsert_step(
            &mut steps,
            StudioArtifactOperatorStep {
                step_id: build_step_id(&run.run_id, StudioArtifactOperatorPhase::AuthorArtifact, 1),
                origin_prompt_event_id: origin_prompt_event_id.clone(),
                phase: StudioArtifactOperatorPhase::AuthorArtifact,
                engine: execution_strategy_id(session.outcome_request.execution_strategy)
                    .to_string(),
                status: author_status,
                label: if author_status == StudioArtifactOperatorRunStatus::Complete {
                    format!("Wrote {target}")
                } else {
                    format!("Write {target}")
                },
                detail: session.artifact_manifest.verification.summary.clone(),
                started_at_ms: run.started_at_ms.saturating_add(4),
                finished_at_ms: (author_status == StudioArtifactOperatorRunStatus::Complete)
                    .then_some(now_ms()),
                preview: live_author_preview(session, &origin_prompt_event_id),
                file_refs: Vec::new(),
                source_refs: run.source_pack.items.clone(),
                verification_refs: Vec::new(),
                attempt: 1,
            },
        );
    }

    if let Some((path, preview, file_refs)) =
        inspect_preview_for_session(session, &origin_prompt_event_id)
    {
        upsert_step(
            &mut steps,
            StudioArtifactOperatorStep {
                step_id: build_step_id(
                    &run.run_id,
                    StudioArtifactOperatorPhase::InspectArtifact,
                    1,
                ),
                origin_prompt_event_id: origin_prompt_event_id.clone(),
                phase: StudioArtifactOperatorPhase::InspectArtifact,
                engine: "artifact_readback".to_string(),
                status: if session.artifact_manifest.files.is_empty() {
                    StudioArtifactOperatorRunStatus::Active
                } else {
                    StudioArtifactOperatorRunStatus::Complete
                },
                label: format!("Inspect {}", basename(&path)),
                detail: format!(
                    "Studio read back the produced artifact output before presentation."
                ),
                started_at_ms: run.started_at_ms.saturating_add(6),
                finished_at_ms: (!session.artifact_manifest.files.is_empty()).then_some(now_ms()),
                preview: Some(preview),
                file_refs,
                source_refs: Vec::new(),
                verification_refs: Vec::new(),
                attempt: 1,
            },
        );
    }

    if let Some(build_session) = build_session {
        let author_status = if build_session.build_status.eq_ignore_ascii_case("failed") {
            StudioArtifactOperatorRunStatus::Blocked
        } else if build_session
            .verification_status
            .eq_ignore_ascii_case("passed")
        {
            StudioArtifactOperatorRunStatus::Complete
        } else {
            StudioArtifactOperatorRunStatus::Active
        };
        upsert_step(
            &mut steps,
            StudioArtifactOperatorStep {
                step_id: build_step_id(&run.run_id, StudioArtifactOperatorPhase::AuthorArtifact, 1),
                origin_prompt_event_id: origin_prompt_event_id.clone(),
                phase: StudioArtifactOperatorPhase::AuthorArtifact,
                engine: "workspace_build".to_string(),
                status: author_status,
                label: format!("Write {}", basename(&build_session.entry_document)),
                detail: studio_session_entry_detail(session, build_session),
                started_at_ms: run.started_at_ms.saturating_add(4),
                finished_at_ms: (author_status == StudioArtifactOperatorRunStatus::Complete)
                    .then_some(now_ms()),
                preview: None,
                file_refs: final_artifacts_for_session(session, &origin_prompt_event_id),
                source_refs: run.source_pack.items.clone(),
                verification_refs: Vec::new(),
                attempt: 1,
            },
        );
        upsert_step(
            &mut steps,
            StudioArtifactOperatorStep {
                step_id: build_step_id(
                    &run.run_id,
                    StudioArtifactOperatorPhase::InspectArtifact,
                    1,
                ),
                origin_prompt_event_id: origin_prompt_event_id.clone(),
                phase: StudioArtifactOperatorPhase::InspectArtifact,
                engine: "workspace_build".to_string(),
                status: if build_session.build_status.eq_ignore_ascii_case("failed") {
                    StudioArtifactOperatorRunStatus::Blocked
                } else {
                    StudioArtifactOperatorRunStatus::Complete
                },
                label: format!("Inspect {}", basename(&build_session.entry_document)),
                detail: format!(
                    "Studio inspected the workspace entry document and preview handoff."
                ),
                started_at_ms: run.started_at_ms.saturating_add(5),
                finished_at_ms: Some(now_ms()),
                preview: None,
                file_refs: final_artifacts_for_session(session, &origin_prompt_event_id),
                source_refs: Vec::new(),
                verification_refs: Vec::new(),
                attempt: 1,
            },
        );
    }

    let session_status = operator_status_for_session(session, build_session);
    if build_session.is_some() || verification_outcome.is_some() || !verification_refs.is_empty() {
        let verification_status = verification_outcome
            .as_ref()
            .map(|outcome| outcome.status)
            .unwrap_or(session_status);
        upsert_step(
            &mut steps,
            StudioArtifactOperatorStep {
                step_id: build_step_id(&run.run_id, StudioArtifactOperatorPhase::VerifyArtifact, 1),
                origin_prompt_event_id: origin_prompt_event_id.clone(),
                phase: StudioArtifactOperatorPhase::VerifyArtifact,
                engine: if matches!(
                    session.artifact_manifest.renderer,
                    StudioRendererKind::HtmlIframe
                        | StudioRendererKind::JsxSandbox
                        | StudioRendererKind::WorkspaceSurface
                ) {
                    "browser_verifier".to_string()
                } else {
                    "artifact_verifier".to_string()
                },
                status: verification_status,
                label: if matches!(
                    session.artifact_manifest.renderer,
                    StudioRendererKind::HtmlIframe
                        | StudioRendererKind::JsxSandbox
                        | StudioRendererKind::WorkspaceSurface
                ) {
                    "Run browser verification".to_string()
                } else {
                    "Verify artifact".to_string()
                },
                detail: verification_outcome
                    .as_ref()
                    .map(|outcome| outcome.summary.clone())
                    .unwrap_or_else(|| session.artifact_manifest.verification.summary.clone()),
                started_at_ms: run.started_at_ms.saturating_add(7),
                finished_at_ms: matches!(
                    verification_status,
                    StudioArtifactOperatorRunStatus::Complete
                        | StudioArtifactOperatorRunStatus::Blocked
                        | StudioArtifactOperatorRunStatus::Failed
                )
                .then_some(now_ms()),
                preview: None,
                file_refs: run.final_artifacts.clone(),
                source_refs: run.source_pack.items.clone(),
                verification_refs,
                attempt: 1,
            },
        );
    }

    let blocked_or_failed_session = matches!(
        session_status,
        StudioArtifactOperatorRunStatus::Blocked | StudioArtifactOperatorRunStatus::Failed
    );
    let session_terminal_ready = session_is_presentable(session)
        && !blocked_or_failed_session
        && matches!(
            session.lifecycle_state,
            StudioArtifactLifecycleState::Ready | StudioArtifactLifecycleState::Partial
        )
        && matches!(session.status.as_str(), "ready" | "partial");
    if session_terminal_ready {
        for step in steps.iter_mut().filter(|step| {
            matches!(
                step.phase,
                StudioArtifactOperatorPhase::AuthorArtifact
                    | StudioArtifactOperatorPhase::RepairArtifact
                    | StudioArtifactOperatorPhase::VerifyArtifact
            ) && step.status == StudioArtifactOperatorRunStatus::Active
        }) {
            step.status = StudioArtifactOperatorRunStatus::Complete;
            step.finished_at_ms.get_or_insert_with(now_ms);
            if step.detail.trim().is_empty() {
                step.detail = session.artifact_manifest.verification.summary.clone();
            }
        }
    }
    let has_active_runtime_step = steps.iter().any(|step| {
        matches!(
            step.phase,
            StudioArtifactOperatorPhase::AuthorArtifact
                | StudioArtifactOperatorPhase::RepairArtifact
                | StudioArtifactOperatorPhase::VerifyArtifact
        ) && step.status == StudioArtifactOperatorRunStatus::Active
    });
    let inspect_settled = steps
        .iter()
        .filter(|step| step.phase == StudioArtifactOperatorPhase::InspectArtifact)
        .all(|step| step_status_is_settled(step.status))
        && steps
            .iter()
            .any(|step| step.phase == StudioArtifactOperatorPhase::InspectArtifact);
    let verify_steps_exist = steps
        .iter()
        .any(|step| step.phase == StudioArtifactOperatorPhase::VerifyArtifact);
    if !has_active_runtime_step && session_is_presentable(session) && verify_steps_exist {
        for step in steps
            .iter_mut()
            .filter(|step| step.phase == StudioArtifactOperatorPhase::VerifyArtifact)
        {
            if !step_status_is_settled(step.status) {
                step.status = if blocked_or_failed_session {
                    session_status
                } else {
                    StudioArtifactOperatorRunStatus::Complete
                };
                step.finished_at_ms.get_or_insert_with(now_ms);
                if step.detail.trim().is_empty() {
                    step.detail = session.artifact_manifest.verification.summary.clone();
                }
            }
        }
    }
    let verify_settled = steps
        .iter()
        .filter(|step| step.phase == StudioArtifactOperatorPhase::VerifyArtifact)
        .all(|step| step_status_is_settled(step.status))
        && steps
            .iter()
            .any(|step| step.phase == StudioArtifactOperatorPhase::VerifyArtifact);
    let can_present = !has_active_runtime_step
        && inspect_settled
        && verify_settled
        && (session_is_presentable(session) || blocked_or_failed_session);
    if can_present {
        let status = if blocked_or_failed_session {
            session_status
        } else {
            StudioArtifactOperatorRunStatus::Complete
        };
        upsert_step(
            &mut steps,
            StudioArtifactOperatorStep {
                step_id: build_step_id(
                    &run.run_id,
                    StudioArtifactOperatorPhase::PresentArtifact,
                    1,
                ),
                origin_prompt_event_id: origin_prompt_event_id.clone(),
                phase: StudioArtifactOperatorPhase::PresentArtifact,
                engine: "studio_surface".to_string(),
                status,
                label: if status == StudioArtifactOperatorRunStatus::Complete {
                    "Open preview".to_string()
                } else {
                    "Present artifact".to_string()
                },
                detail: session.artifact_manifest.verification.summary.clone(),
                started_at_ms: run.started_at_ms.saturating_add(9),
                finished_at_ms: Some(now_ms()),
                preview: None,
                file_refs: run.final_artifacts.clone(),
                source_refs: Vec::new(),
                verification_refs: Vec::new(),
                attempt: 1,
            },
        );
    }

    steps.sort_by(|left, right| {
        phase_rank(left.phase, left.attempt)
            .cmp(&phase_rank(right.phase, right.attempt))
            .then_with(|| left.started_at_ms.cmp(&right.started_at_ms))
            .then_with(|| left.step_id.cmp(&right.step_id))
    });

    run.repair_count = steps
        .iter()
        .filter(|step| step.phase == StudioArtifactOperatorPhase::RepairArtifact)
        .count() as u32;
    run.steps = steps;
    run.verification_outcome = verification_outcome;
    let present_settled = run.steps.iter().any(|step| {
        step.phase == StudioArtifactOperatorPhase::PresentArtifact
            && step_status_is_settled(step.status)
    });
    run.status = if has_active_runtime_step {
        StudioArtifactOperatorRunStatus::Active
    } else if present_settled {
        session_status
    } else if blocked_or_failed_session && verify_settled {
        session_status
    } else {
        StudioArtifactOperatorRunStatus::Active
    };
    if matches!(
        run.status,
        StudioArtifactOperatorRunStatus::Complete
            | StudioArtifactOperatorRunStatus::Blocked
            | StudioArtifactOperatorRunStatus::Failed
    ) {
        run.finished_at_ms = Some(now_ms());
    } else {
        run.finished_at_ms = None;
    }

    session.materialization.operator_steps = run.steps.clone();
    session.active_operator_run = Some(run);
}

fn studio_session_entry_detail(
    session: &StudioArtifactSession,
    build_session: &BuildArtifactSession,
) -> String {
    if build_session
        .verification_status
        .eq_ignore_ascii_case("passed")
    {
        "Studio finished the workspace build and can now open the verified preview.".to_string()
    } else if build_session.build_status.eq_ignore_ascii_case("failed")
        || build_session
            .verification_status
            .eq_ignore_ascii_case("failed")
    {
        build_session
            .last_failure_summary
            .clone()
            .unwrap_or_else(|| session.artifact_manifest.verification.summary.clone())
    } else {
        session.artifact_manifest.verification.summary.clone()
    }
}
