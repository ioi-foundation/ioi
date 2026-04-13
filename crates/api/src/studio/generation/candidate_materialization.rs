use super::*;

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
        "artifact_generation:candidate_judge:start id={}",
        candidate_id
    ));
    let judge = match await_with_activity_heartbeat(
        judge_candidate_with_runtime_and_render_eval(
            production_runtime,
            render_evaluation.as_ref(),
            title,
            request,
            brief,
            edit_intent,
            &payload,
        ),
        activity_observer,
        Duration::from_millis(125),
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

pub(super) fn local_download_bundle_candidate_prejudge(
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

pub(super) fn local_draft_fast_path_enabled(
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

pub(super) fn judge_supports_local_draft_surface(judge: &StudioArtifactJudgeResult) -> bool {
    judge.classification != StudioArtifactJudgeClassification::Blocked
        && judge.deserves_primary_artifact_view
        && !judge.generic_shell_detected
        && !judge.trivial_shell_detected
}

pub(super) fn candidate_supports_pending_draft_surface(
    summary: &StudioArtifactCandidateSummary,
) -> bool {
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
        blocked_reasons.first().cloned().unwrap_or_else(|| {
            "Direct-authored draft could not be surfaced for acceptance.".to_string()
        })
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
        deserves_primary_artifact_view: !renderable_paths.is_empty()
            && blocked_render_finding.is_none(),
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

pub(super) fn direct_author_should_defer_render_evaluation(
    request: &StudioOutcomeArtifactRequest,
    runtime_kind: StudioRuntimeProvenanceKind,
) -> bool {
    runtime_kind == StudioRuntimeProvenanceKind::RealLocalRuntime
        && matches!(request.renderer, StudioRendererKind::HtmlIframe)
}

pub(super) fn local_draft_pending_acceptance_judge(
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

pub(super) fn build_non_swarm_draft_bundle(
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

pub(super) fn record_adaptive_search_signal(
    signals: &mut Vec<StudioAdaptiveSearchSignal>,
    signal: StudioAdaptiveSearchSignal,
) {
    if !signals.contains(&signal) {
        signals.push(signal);
    }
}
