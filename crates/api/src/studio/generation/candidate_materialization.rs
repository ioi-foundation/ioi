use super::*;
use crate::studio::payload::{
    download_bundle_export_body_looks_complete, download_bundle_export_format_label,
    infer_download_bundle_export_format_from_path_and_mime, is_download_bundle_readme_file,
};
use std::time::Duration;

pub(super) async fn materialize_and_locally_judge_candidate(
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
    activity_observer: Option<StudioArtifactActivityObserver>,
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
        activity_observer.clone(),
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

    let render_eval_future = evaluate_candidate_render_with_fallback(
        render_evaluator,
        request,
        brief,
        blueprint,
        artifact_ir,
        edit_intent,
        &payload,
        production_provenance.kind,
    );
    let render_evaluation = if render_eval_timeout_for_runtime(
        request.renderer,
        production_provenance.kind,
    )
    .is_some()
    {
        await_with_activity_heartbeat(
            render_eval_future,
            activity_observer.clone(),
            Duration::from_millis(125),
        )
        .await
    } else {
        render_eval_future.await
    };

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
        "artifact_generation:candidate_judge:render_sanity id={}",
        candidate_id
    ));
    let judge = render_sanity_candidate_judge(request, brief, &payload, render_evaluation.as_ref());
    studio_generation_trace(format!(
        "artifact_generation:candidate_judge:ok id={} classification={:?}",
        candidate_id, judge.classification
    ));

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

pub(crate) fn local_download_bundle_candidate_prejudge(
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
    let recognized_exports = export_files
        .iter()
        .filter_map(|file| {
            if is_download_bundle_readme_file(&file.path, &file.mime) {
                None
            } else {
                infer_download_bundle_export_format_from_path_and_mime(&file.path, &file.mime)
                    .map(|format| (file, format))
            }
        })
        .collect::<Vec<_>>();
    let has_usable_export = recognized_exports
        .iter()
        .any(|(file, format)| download_bundle_export_body_looks_complete(*format, &file.body));
    let export_labels = recognized_exports
        .iter()
        .map(|(_, format)| download_bundle_export_format_label(*format))
        .collect::<Vec<_>>();
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
    let classification = if has_readme && has_usable_export && all_downloadable {
        StudioArtifactJudgeClassification::Pass
    } else if has_readme || has_usable_export {
        StudioArtifactJudgeClassification::Repairable
    } else {
        StudioArtifactJudgeClassification::Blocked
    };
    let request_faithfulness = if has_readme && has_usable_export {
        4
    } else {
        2
    };
    let concept_coverage = if concept_hits >= brief.required_concepts.len().min(2).max(1) {
        4
    } else if has_readme && has_usable_export {
        3
    } else {
        2
    };
    let completeness = if has_readme && has_usable_export {
        4
    } else {
        2
    };
    let deserves_primary_artifact_view = classification == StudioArtifactJudgeClassification::Pass;
    let mut strengths = Vec::new();
    if has_readme {
        strengths.push("README.md is present for bundle guidance.".to_string());
    }
    if !export_labels.is_empty() && has_usable_export {
        strengths.push(format!(
            "{} is present with usable content.",
            export_labels.join(" + ")
        ));
    }
    let mut blocked_reasons = Vec::new();
    if !has_readme {
        blocked_reasons.push("Bundle is missing a usable README.md.".to_string());
    }
    if !has_usable_export {
        blocked_reasons
            .push("Bundle is missing a usable request-grounded export file.".to_string());
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
            trivial_shell_detected: !(has_readme || has_usable_export),
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

fn render_sanity_issue_snapshot(
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
) -> (Vec<String>, Vec<String>) {
    let Some(render_evaluation) = render_evaluation else {
        return (Vec::new(), Vec::new());
    };

    let mut issue_classes = Vec::new();
    let mut repair_hints = Vec::new();

    for finding in render_evaluation.findings.iter().take(3) {
        if !finding.code.is_empty() && !issue_classes.contains(&finding.code) {
            issue_classes.push(finding.code.clone());
        }
        if repair_hints.len() < 3 {
            repair_hints.push(finding.summary.clone());
        }
    }

    for obligation in render_evaluation
        .acceptance_obligations
        .iter()
        .filter(|obligation| {
            matches!(
                obligation.status,
                StudioArtifactAcceptanceObligationStatus::Failed
                    | StudioArtifactAcceptanceObligationStatus::Blocked
            )
        })
    {
        if !issue_classes.contains(&obligation.obligation_id) {
            issue_classes.push(obligation.obligation_id.clone());
        }
        if repair_hints.len() < 3 {
            repair_hints.push(
                obligation
                    .detail
                    .clone()
                    .unwrap_or_else(|| obligation.summary.clone()),
            );
        }
    }

    (issue_classes, repair_hints)
}

pub(super) fn render_sanity_block_reason(
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
) -> Option<String> {
    let render_evaluation = render_evaluation?;
    if !render_evaluation.supported {
        return None;
    }

    if let Some(reason) = direct_author_runtime_failure_reason(Some(render_evaluation)) {
        return Some(reason);
    }

    if let Some(obligation) = render_evaluation
        .acceptance_obligations
        .iter()
        .find(|obligation| {
            matches!(
                obligation.status,
                StudioArtifactAcceptanceObligationStatus::Failed
                    | StudioArtifactAcceptanceObligationStatus::Blocked
            )
        })
    {
        return Some(
            obligation
                .detail
                .clone()
                .unwrap_or_else(|| obligation.summary.clone()),
        );
    }

    render_evaluation
        .findings
        .iter()
        .find(|finding| finding.severity == StudioArtifactRenderFindingSeverity::Blocked)
        .map(|finding| finding.summary.clone())
}

pub(super) fn render_sanity_repair_reason(
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
) -> Option<String> {
    let render_evaluation = render_evaluation?;
    if !render_evaluation.supported {
        return None;
    }

    if let Some(reason) = render_sanity_block_reason(Some(render_evaluation)) {
        return Some(reason);
    }

    render_evaluation
        .findings
        .iter()
        .find(|finding| {
            matches!(
                finding.severity,
                StudioArtifactRenderFindingSeverity::Info
                    | StudioArtifactRenderFindingSeverity::Warning
            )
        })
        .map(|finding| finding.summary.clone())
}

pub(super) fn render_sanity_candidate_judge(
    request: &StudioOutcomeArtifactRequest,
    brief: &StudioArtifactBrief,
    payload: &StudioGeneratedArtifactPayload,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
) -> StudioArtifactJudgeResult {
    let renderable_paths = payload
        .files
        .iter()
        .filter(|file| file.renderable)
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    let blocked_reason = render_sanity_block_reason(render_evaluation);
    let repair_reason = render_sanity_repair_reason(render_evaluation);
    let classification = if renderable_paths.is_empty() {
        StudioArtifactJudgeClassification::Blocked
    } else if repair_reason.is_some() {
        StudioArtifactJudgeClassification::Repairable
    } else {
        StudioArtifactJudgeClassification::Pass
    };
    let mut blocked_reasons = Vec::new();
    if renderable_paths.is_empty() {
        blocked_reasons.push("Artifact did not surface a renderable file.".to_string());
    }
    if let Some(reason) = blocked_reason.as_ref() {
        blocked_reasons.push(reason.clone());
    }

    let (mut issue_classes, mut repair_hints) = render_sanity_issue_snapshot(render_evaluation);
    if let Some(reason) = repair_reason.as_ref() {
        if !repair_hints.iter().any(|hint| hint == reason) {
            repair_hints.insert(0, reason.clone());
        }
        let synthetic_issue = if direct_author_runtime_failure_reason(render_evaluation).is_some() {
            "runtime_error"
        } else {
            "render_sanity"
        };
        if !issue_classes.iter().any(|issue| issue == synthetic_issue) {
            issue_classes.push(synthetic_issue.to_string());
        }
    }

    super::enforce_renderer_judge_contract(
        request,
        brief,
        payload,
        StudioArtifactJudgeResult {
            classification,
            request_faithfulness: if renderable_paths.is_empty() { 1 } else { 4 },
            concept_coverage: if renderable_paths.is_empty() { 1 } else { 4 },
            interaction_relevance: if renderable_paths.is_empty() {
                1
            } else if repair_reason.is_some() {
                3
            } else {
                4
            },
            layout_coherence: if renderable_paths.is_empty() { 1 } else { 4 },
            visual_hierarchy: if renderable_paths.is_empty() { 1 } else { 4 },
            completeness: if renderable_paths.is_empty() {
                1
            } else if repair_reason.is_some() {
                3
            } else {
                4
            },
            generic_shell_detected: false,
            trivial_shell_detected: renderable_paths.is_empty(),
            deserves_primary_artifact_view: !renderable_paths.is_empty(),
            patched_existing_artifact: None,
            continuity_revision_ux: None,
            issue_classes,
            repair_hints,
            strengths: if renderable_paths.is_empty() {
                Vec::new()
            } else if repair_reason.is_some() {
                vec![
                    "Studio surfaced the artifact quickly while keeping repair bounded to concrete render issues."
                        .to_string(),
                ]
            } else {
                vec![
                    "Fast render sanity cleared the artifact for immediate presentation."
                        .to_string(),
                ]
            },
            blocked_reasons,
            file_findings: renderable_paths
                .iter()
                .map(|path| format!("draft surfaced: {path}"))
                .collect(),
            aesthetic_verdict: if renderable_paths.is_empty() {
                "No renderable artifact surfaced yet.".to_string()
            } else {
                "A request-specific artifact surfaced for immediate review.".to_string()
            },
            interaction_verdict: if let Some(reason) = repair_reason.as_ref() {
                format!("Render sanity found a concrete issue that should drive bounded repair: {reason}")
            } else if renderable_paths.is_empty() {
                "Interaction quality cannot be judged until a renderable file exists.".to_string()
            } else {
                "Render sanity cleared the surfaced artifact without a blocking runtime or render failure."
                    .to_string()
            },
            truthfulness_warnings: Vec::new(),
            recommended_next_pass: Some(
                if renderable_paths.is_empty() || repair_reason.is_some() {
                    "structural_repair"
                } else {
                    "surface"
                }
                .to_string(),
            ),
            strongest_contradiction: repair_reason.clone(),
            rationale: if renderable_paths.is_empty() {
                "Studio could not surface a renderable artifact.".to_string()
            } else if repair_reason.is_some() {
                "Studio surfaced the artifact and kept follow-up repair bounded to concrete render sanity failures."
                    .to_string()
            } else {
                "Studio used fast render sanity to clear the artifact for immediate presentation."
                    .to_string()
            },
        },
    )
}

pub(super) fn candidate_supports_fast_surface(summary: &StudioArtifactCandidateSummary) -> bool {
    if summary.judge.classification == StudioArtifactJudgeClassification::Blocked
        || summary.judge.generic_shell_detected
        || summary.judge.trivial_shell_detected
    {
        return false;
    }

    if summary.renderable_paths.is_empty() && !summary.judge.deserves_primary_artifact_view {
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

pub(super) fn direct_author_provisional_candidate_judge(
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
        StudioArtifactJudgeClassification::Pass
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
            .unwrap_or_else(|| "Direct-authored artifact could not be surfaced.".to_string())
    } else {
        "Studio surfaced a renderable direct-authored artifact without waiting on the slow acceptance gate."
            .to_string()
    };
    StudioArtifactJudgeResult {
        classification,
        request_faithfulness: if renderable_paths.is_empty() { 1 } else { 4 },
        concept_coverage: if renderable_paths.is_empty() { 1 } else { 4 },
        interaction_relevance: if renderable_paths.is_empty() { 1 } else { 4 },
        layout_coherence: if renderable_paths.is_empty() { 1 } else { 4 },
        visual_hierarchy: if renderable_paths.is_empty() { 1 } else { 4 },
        completeness: if renderable_paths.is_empty() { 1 } else { 4 },
        generic_shell_detected: false,
        trivial_shell_detected: renderable_paths.is_empty(),
        deserves_primary_artifact_view: !renderable_paths.is_empty()
            && blocked_render_finding.is_none(),
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        issue_classes,
        repair_hints,
        strengths: if renderable_paths.is_empty() {
            Vec::new()
        } else {
            vec!["Renderable direct-authored artifact surfaced immediately.".to_string()]
        },
        blocked_reasons,
        file_findings: renderable_paths
            .iter()
            .map(|path| format!("draft surfaced: {path}"))
            .collect(),
        aesthetic_verdict: if renderable_paths.is_empty() {
            "No renderable direct-authored artifact surfaced.".to_string()
        } else {
            "Renderable artifact surfaced cleanly enough for immediate review.".to_string()
        },
        interaction_verdict: if renderable_paths.is_empty() {
            "Interaction quality cannot be judged until a renderable file exists.".to_string()
        } else {
            "Interaction quality is judged from the surfaced artifact and any render findings."
                .to_string()
        },
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some(
            if classification == StudioArtifactJudgeClassification::Blocked {
                "structural_repair"
            } else {
                "surface"
            }
            .to_string(),
        ),
        strongest_contradiction: blocked_render_finding.map(|finding| finding.summary.clone()),
        rationale,
    }
}

pub(super) fn direct_author_fast_runtime_sanity_enabled(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> bool {
    runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && request.renderer == StudioRendererKind::HtmlIframe
}

pub(super) fn direct_author_fast_runtime_sanity_timeout(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> Option<Duration> {
    if direct_author_fast_runtime_sanity_enabled(request, runtime_kind) {
        Some(Duration::from_secs(8))
    } else {
        None
    }
}

pub(super) fn direct_author_runtime_failure_reason(
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
) -> Option<String> {
    let render_evaluation = render_evaluation?;
    if let Some(obligation) = render_evaluation
        .acceptance_obligations
        .iter()
        .find(|obligation| {
            obligation.obligation_id == "runtime_boot_clean"
                && matches!(
                    obligation.status,
                    StudioArtifactAcceptanceObligationStatus::Failed
                        | StudioArtifactAcceptanceObligationStatus::Blocked
                )
        })
    {
        return Some(
            obligation
                .detail
                .clone()
                .unwrap_or_else(|| obligation.summary.clone()),
        );
    }

    if let Some(witness) = render_evaluation
        .execution_witnesses
        .iter()
        .find(|witness| !witness.console_errors.is_empty())
    {
        return Some(
            witness
                .detail
                .clone()
                .unwrap_or_else(|| witness.console_errors.join(" | ")),
        );
    }

    render_evaluation
        .findings
        .iter()
        .find(|finding| {
            let summary = finding.summary.to_ascii_lowercase();
            summary.contains("runtime error")
                || summary.contains("unhandledrejection")
                || summary.contains("referenceerror")
                || summary.contains("typeerror")
        })
        .map(|finding| finding.summary.clone())
}

pub(super) fn direct_author_runtime_sanity_judge(
    payload: &StudioGeneratedArtifactPayload,
    render_evaluation: Option<&StudioArtifactRenderEvaluation>,
) -> StudioArtifactJudgeResult {
    let renderable_paths = payload
        .files
        .iter()
        .filter(|file| file.renderable)
        .map(|file| file.path.clone())
        .collect::<Vec<_>>();
    let runtime_failure = direct_author_runtime_failure_reason(render_evaluation);
    let classification = if renderable_paths.is_empty() {
        StudioArtifactJudgeClassification::Blocked
    } else if runtime_failure.is_some() {
        StudioArtifactJudgeClassification::Repairable
    } else {
        StudioArtifactJudgeClassification::Pass
    };
    let contradiction = runtime_failure.clone();
    let mut issue_classes = Vec::new();
    let mut repair_hints = Vec::new();
    if let Some(render_evaluation) = render_evaluation {
        for finding in render_evaluation.findings.iter().take(3) {
            if !issue_classes.contains(&finding.code) {
                issue_classes.push(finding.code.clone());
            }
            if repair_hints.len() < 3 {
                repair_hints.push(finding.summary.clone());
            }
        }
    }
    if runtime_failure.is_some() && !issue_classes.iter().any(|issue| issue == "runtime_error") {
        issue_classes.push("runtime_error".to_string());
    }
    if let Some(reason) = runtime_failure.as_ref() {
        if !repair_hints.iter().any(|hint| hint == reason) {
            repair_hints.insert(0, reason.clone());
        }
    }

    StudioArtifactJudgeResult {
        classification,
        request_faithfulness: if renderable_paths.is_empty() { 1 } else { 4 },
        concept_coverage: if renderable_paths.is_empty() { 1 } else { 4 },
        interaction_relevance: if renderable_paths.is_empty() {
            1
        } else if runtime_failure.is_some() {
            3
        } else {
            4
        },
        layout_coherence: if renderable_paths.is_empty() { 1 } else { 4 },
        visual_hierarchy: if renderable_paths.is_empty() { 1 } else { 4 },
        completeness: if renderable_paths.is_empty() {
            1
        } else if runtime_failure.is_some() {
            3
        } else {
            4
        },
        generic_shell_detected: false,
        trivial_shell_detected: renderable_paths.is_empty(),
        deserves_primary_artifact_view: !renderable_paths.is_empty(),
        patched_existing_artifact: None,
        continuity_revision_ux: None,
        issue_classes,
        repair_hints,
        strengths: if renderable_paths.is_empty() {
            Vec::new()
        } else if runtime_failure.is_some() {
            vec![
                "Studio kept a surfaced draft available while runtime repair remained bounded."
                    .to_string(),
            ]
        } else {
            vec![
                "Runtime sanity cleared the surfaced direct-authored draft for immediate presentation."
                    .to_string(),
            ]
        },
        blocked_reasons: contradiction.clone().into_iter().collect(),
        file_findings: renderable_paths
            .iter()
            .map(|path| format!("draft surfaced: {path}"))
            .collect(),
        aesthetic_verdict: if renderable_paths.is_empty() {
            "No renderable direct-authored draft surfaced yet.".to_string()
        } else {
            "Studio surfaced a request-specific direct-authored artifact.".to_string()
        },
        interaction_verdict: if let Some(reason) = runtime_failure.as_ref() {
            format!("Runtime sanity still found a concrete execution issue: {reason}")
        } else if renderable_paths.is_empty() {
            "Interaction quality cannot be judged until a renderable file exists.".to_string()
        } else {
            "Runtime sanity cleared the rendered interaction path without a blocking console failure."
                .to_string()
        },
        truthfulness_warnings: Vec::new(),
        recommended_next_pass: Some(
            if renderable_paths.is_empty() {
                "structural_repair"
            } else if runtime_failure.is_some() {
                "structural_repair"
            } else {
                "accept"
            }
            .to_string(),
        ),
        strongest_contradiction: contradiction,
        rationale: if renderable_paths.is_empty() {
            "Direct-authored draft could not be surfaced.".to_string()
        } else if runtime_failure.is_some() {
            "Studio surfaced the draft immediately after bounded runtime repair attempts."
                .to_string()
        } else {
            "Studio replaced slow acceptance with a fast runtime-sanity pass and surfaced the draft immediately."
                .to_string()
        },
    }
}

pub(super) fn record_adaptive_search_signal(
    signals: &mut Vec<StudioAdaptiveSearchSignal>,
    signal: StudioAdaptiveSearchSignal,
) {
    if !signals.contains(&signal) {
        signals.push(signal);
    }
}
