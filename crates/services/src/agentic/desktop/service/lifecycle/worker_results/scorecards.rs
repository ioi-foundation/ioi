use super::*;

pub(crate) fn build_research_verification_scorecard(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ResearchVerificationScorecard> {
    if run.playbook_id.trim() != "citation_grounded_brief" {
        return None;
    }
    let step = playbook.steps.get(step_idx)?;
    if step.step_id.trim() != "verify" {
        return None;
    }

    let research_brief_text = run
        .steps
        .iter()
        .find(|candidate| candidate.step_id == "research")
        .and_then(|candidate| {
            candidate
                .child_session_id
                .and_then(|child_session_id| {
                    load_worker_session_result(state, child_session_id)
                        .ok()
                        .flatten()
                })
                .and_then(|worker_result| worker_result.raw_output)
                .or_else(|| candidate.output_preview.clone())
        });
    let (source_count, distinct_domain_count) =
        count_research_brief_sources(research_brief_text.as_deref().unwrap_or_default());
    let scorecard_fields = parse_scorecard_fields(
        result
            .raw_output
            .as_deref()
            .unwrap_or(result.merged_output.as_str()),
    );
    let notes = first_scorecard_note(
        &scorecard_fields,
        &[
            "notes",
            "note",
            "blockers",
            "blocker",
            "next_checks",
            "next_check",
        ],
    );
    let fallback_verdict = if result.success { "unknown" } else { "blocked" };

    Some(ResearchVerificationScorecard {
        verdict: normalize_research_verifier_status(
            scorecard_fields.get("verdict").map(String::as_str),
            fallback_verdict,
        ),
        source_count,
        distinct_domain_count,
        source_count_floor_met: source_count >= RESEARCH_SOURCE_FLOOR,
        source_independence_floor_met: distinct_domain_count >= RESEARCH_DOMAIN_FLOOR,
        freshness_status: normalize_research_verifier_status(
            scorecard_fields
                .get("freshness_status")
                .or_else(|| scorecard_fields.get("freshness"))
                .map(String::as_str),
            "unknown",
        ),
        quote_grounding_status: normalize_research_verifier_status(
            scorecard_fields
                .get("quote_grounding_status")
                .or_else(|| scorecard_fields.get("quote_grounding"))
                .or_else(|| scorecard_fields.get("quote_grounding_check"))
                .map(String::as_str),
            "unknown",
        ),
        notes,
    })
}

pub(crate) fn parent_playbook_research_scorecard(
    run: &ParentPlaybookRun,
) -> Option<ResearchVerificationScorecard> {
    run.steps
        .iter()
        .rev()
        .find_map(|step| step.research_scorecard.clone())
}

pub(crate) fn build_artifact_generation_summary(
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ArtifactGenerationSummary> {
    if run.playbook_id.trim() != "artifact_generation_gate" {
        return None;
    }
    let step = playbook.steps.get(step_idx)?;
    if step.step_id.trim() != "build" {
        return None;
    }

    let fields = parse_scorecard_fields(
        result
            .raw_output
            .as_deref()
            .unwrap_or(result.merged_output.as_str()),
    );
    let produced_files = fields
        .get("produced_files")
        .or_else(|| fields.get("files"))
        .or_else(|| fields.get("outputs"))
        .map(String::as_str)
        .unwrap_or_default();
    let notes = first_scorecard_note(
        &fields,
        &[
            "notes",
            "note",
            "remaining_gaps",
            "remaining_gap",
            "blockers",
            "blocker",
        ],
    );
    let fallback_status = if result.success {
        "generated"
    } else {
        "blocked"
    };

    Some(ArtifactGenerationSummary {
        status: normalize_artifact_generation_status(
            fields.get("status").map(String::as_str),
            fallback_status,
        ),
        produced_file_count: count_compact_list_items(produced_files),
        verification_signal_status: normalize_artifact_signal_status(
            fields
                .get("verification_signal_status")
                .or_else(|| fields.get("verification_signals"))
                .or_else(|| fields.get("verification_notes"))
                .map(String::as_str),
            "unknown",
        ),
        presentation_status: normalize_artifact_presentation_status(
            fields
                .get("presentation_status")
                .or_else(|| fields.get("presentation_readiness"))
                .map(String::as_str),
            "unknown",
        ),
        notes,
    })
}

pub(crate) fn parent_playbook_artifact_generation(
    run: &ParentPlaybookRun,
) -> Option<ArtifactGenerationSummary> {
    run.steps
        .iter()
        .rev()
        .find_map(|step| step.artifact_generation.clone())
}

pub(crate) fn build_artifact_quality_scorecard(
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ArtifactQualityScorecard> {
    if run.playbook_id.trim() != "artifact_generation_gate" {
        return None;
    }
    let step = playbook.steps.get(step_idx)?;
    if step.step_id.trim() != "judge" {
        return None;
    }

    let fields = parse_scorecard_fields(
        result
            .raw_output
            .as_deref()
            .unwrap_or(result.merged_output.as_str()),
    );
    let notes = first_scorecard_note(
        &fields,
        &[
            "notes",
            "note",
            "blockers",
            "blocker",
            "repair_reason",
            "reason",
        ],
    );
    let fallback_verdict = if result.success { "unknown" } else { "blocked" };

    Some(ArtifactQualityScorecard {
        verdict: normalize_artifact_verdict(
            fields.get("verdict").map(String::as_str),
            fallback_verdict,
        ),
        fidelity_status: normalize_artifact_fidelity_status(
            fields
                .get("fidelity_status")
                .or_else(|| fields.get("fidelity"))
                .map(String::as_str),
            "unknown",
        ),
        presentation_status: normalize_artifact_presentation_status(
            fields
                .get("presentation_status")
                .or_else(|| fields.get("presentation_readiness"))
                .map(String::as_str),
            "unknown",
        ),
        repair_status: normalize_artifact_repair_status(
            fields.get("repair_status").map(String::as_str),
            "unknown",
        ),
        notes,
    })
}

pub(crate) fn parent_playbook_artifact_quality(
    run: &ParentPlaybookRun,
) -> Option<ArtifactQualityScorecard> {
    run.steps
        .iter()
        .rev()
        .find_map(|step| step.artifact_quality.clone())
}

pub(crate) fn build_artifact_repair_summary(
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ArtifactRepairSummary> {
    if run.playbook_id.trim() != "artifact_generation_gate" {
        return None;
    }
    let step = playbook.steps.get(step_idx)?;
    if !matches!(step.step_id.trim(), "build" | "judge") {
        return None;
    }

    let fields = parse_scorecard_fields(
        result
            .raw_output
            .as_deref()
            .unwrap_or(result.merged_output.as_str()),
    );
    let presentation_status = normalize_artifact_presentation_status(
        fields
            .get("presentation_status")
            .or_else(|| fields.get("presentation_readiness"))
            .map(String::as_str),
        "unknown",
    );
    let repair_fallback = match presentation_status.as_str() {
        "ready" => "not_needed",
        "needs_repair" => "required",
        "needs_judge" => "recommended",
        "blocked" => "blocked",
        _ if result.success => "unknown",
        _ => "blocked",
    };

    Some(ArtifactRepairSummary {
        status: normalize_artifact_repair_status(
            fields.get("repair_status").map(String::as_str),
            repair_fallback,
        ),
        reason: first_scorecard_note(
            &fields,
            &[
                "repair_reason",
                "reason",
                "notes",
                "note",
                "blockers",
                "blocker",
            ],
        ),
        next_step: first_scorecard_note(&fields, &["next_repair_step", "next_step", "next_action"]),
    })
}

pub(crate) fn parent_playbook_artifact_repair(
    run: &ParentPlaybookRun,
) -> Option<ArtifactRepairSummary> {
    run.steps
        .iter()
        .rev()
        .find_map(|step| step.artifact_repair.clone())
}

pub(crate) fn build_computer_use_perception_summary(
    _state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ComputerUsePerceptionSummary> {
    if run.playbook_id.trim() != "browser_postcondition_gate" {
        return None;
    }
    let step = playbook.steps.get(step_idx)?;
    if step.step_id.trim() != "perceive" {
        return None;
    }

    let fields = parse_scorecard_fields(
        result
            .raw_output
            .as_deref()
            .unwrap_or(result.merged_output.as_str()),
    );
    let notes = first_scorecard_note(
        &fields,
        &[
            "notes",
            "note",
            "ambiguities",
            "ambiguity",
            "blockers",
            "blocker",
        ],
    );
    let ui_state = fields
        .get("ui_state")
        .or_else(|| fields.get("surface"))
        .cloned()
        .or_else(|| notes.clone())
        .unwrap_or_else(|| "UI state not summarized.".to_string());

    Some(ComputerUsePerceptionSummary {
        surface_status: normalize_computer_use_surface_status(
            fields.get("surface_status").map(String::as_str),
            if result.success { "unknown" } else { "blocked" },
        ),
        ui_state,
        target: first_scorecard_note(
            &fields,
            &["target", "likely_target", "missing_prerequisite"],
        ),
        approval_risk: normalize_computer_use_approval_risk(
            fields
                .get("approval_risk")
                .or_else(|| fields.get("approval_state"))
                .map(String::as_str),
        ),
        next_action: first_scorecard_note(
            &fields,
            &["next_action", "next_safe_action", "next_step"],
        ),
        notes,
    })
}

pub(crate) fn parent_playbook_computer_use_perception(
    run: &ParentPlaybookRun,
) -> Option<ComputerUsePerceptionSummary> {
    run.steps
        .iter()
        .rev()
        .find_map(|step| step.computer_use_perception.clone())
}

pub(crate) fn build_coding_verification_scorecard(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<CodingVerificationScorecard> {
    if run.playbook_id.trim() != "evidence_audited_patch" {
        return None;
    }
    let step = playbook.steps.get(step_idx)?;
    if step.step_id.trim() != "verify" {
        return None;
    }

    let implement_output = load_step_raw_output(state, run, "implement").unwrap_or_default();
    let verification_items = extract_prefixed_items(
        &implement_output,
        &["Verification:", "Targeted verification:"],
    );
    let scorecard_fields = parse_scorecard_fields(
        result
            .raw_output
            .as_deref()
            .unwrap_or(result.merged_output.as_str()),
    );
    let targeted_command_count = scorecard_fields
        .get("targeted_command_count")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(verification_items.len() as u32);
    let targeted_pass_count = scorecard_fields
        .get("targeted_pass_count")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or_else(|| {
            let passed = count_passed_items(&verification_items);
            if passed == 0
                && targeted_command_count > 0
                && normalize_coding_verdict(
                    scorecard_fields.get("verdict").map(String::as_str),
                    if result.success { "unknown" } else { "blocked" },
                ) == "passed"
            {
                targeted_command_count
            } else {
                passed
            }
        });
    let notes = first_scorecard_note(
        &scorecard_fields,
        &[
            "notes",
            "note",
            "blockers",
            "blocker",
            "next_checks",
            "next_check",
        ],
    );
    let fallback_verdict = if result.success { "unknown" } else { "blocked" };

    Some(CodingVerificationScorecard {
        verdict: normalize_coding_verdict(
            scorecard_fields.get("verdict").map(String::as_str),
            fallback_verdict,
        ),
        targeted_command_count,
        targeted_pass_count,
        widening_status: normalize_widening_status(
            scorecard_fields
                .get("widening_status")
                .or_else(|| scorecard_fields.get("widened"))
                .map(String::as_str),
        ),
        regression_status: normalize_regression_status(
            scorecard_fields
                .get("regression_status")
                .or_else(|| scorecard_fields.get("regressions"))
                .map(String::as_str),
        ),
        notes,
    })
}

pub(crate) fn parent_playbook_coding_scorecard(
    run: &ParentPlaybookRun,
) -> Option<CodingVerificationScorecard> {
    run.steps
        .iter()
        .rev()
        .find_map(|step| step.coding_scorecard.clone())
}

pub(crate) fn build_computer_use_verification_scorecard(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ComputerUseVerificationScorecard> {
    if run.playbook_id.trim() != "browser_postcondition_gate" {
        return None;
    }
    let step = playbook.steps.get(step_idx)?;
    if step.step_id.trim() != "verify" {
        return None;
    }

    let execute_output = load_step_raw_output(state, run, "execute").unwrap_or_default();
    let execute_fields = parse_scorecard_fields(&execute_output);
    let verify_fields = parse_scorecard_fields(
        result
            .raw_output
            .as_deref()
            .unwrap_or(result.merged_output.as_str()),
    );
    let notes = first_scorecard_note(
        &verify_fields,
        &[
            "notes",
            "note",
            "blockers",
            "blocker",
            "next_checks",
            "next_check",
        ],
    )
    .or_else(|| {
        first_scorecard_note(
            &execute_fields,
            &["notes", "note", "blocker_summary", "blockers", "blocker"],
        )
    });
    let fallback_verdict = if result.success { "unknown" } else { "blocked" };
    let observed_postcondition = first_scorecard_note(
        &execute_fields,
        &["observed_postcondition", "postcondition"],
    )
    .or_else(|| first_scorecard_note(&verify_fields, &["observed_postcondition", "postcondition"]));
    let approval_state = normalize_computer_use_approval_state(
        verify_fields
            .get("approval_state")
            .or_else(|| execute_fields.get("approval_state"))
            .or_else(|| execute_fields.get("approval_risk"))
            .map(String::as_str),
        "unknown",
    );
    let recovery_status = normalize_computer_use_recovery_status(
        verify_fields
            .get("recovery_status")
            .or_else(|| execute_fields.get("recovery_status"))
            .map(String::as_str),
        if approval_state == "pending" {
            "pending_approval"
        } else {
            "unknown"
        },
    );
    let verdict = normalize_computer_use_verdict(
        verify_fields.get("verdict").map(String::as_str),
        fallback_verdict,
    );

    Some(ComputerUseVerificationScorecard {
        verdict: verdict.clone(),
        postcondition_status: normalize_computer_use_postcondition_status(
            verify_fields
                .get("postcondition_status")
                .or_else(|| verify_fields.get("postcondition"))
                .map(String::as_str),
            if verdict == "passed" {
                "met"
            } else if verdict == "blocked" {
                "blocked"
            } else {
                "open"
            },
        ),
        approval_state,
        recovery_status,
        observed_postcondition,
        notes,
    })
}

pub(crate) fn parent_playbook_computer_use_verification(
    run: &ParentPlaybookRun,
) -> Option<ComputerUseVerificationScorecard> {
    run.steps
        .iter()
        .rev()
        .find_map(|step| step.computer_use_verification.clone())
}

pub(crate) fn build_patch_synthesis_summary(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<PatchSynthesisSummary> {
    if run.playbook_id.trim() != "evidence_audited_patch" {
        return None;
    }
    let step = playbook.steps.get(step_idx)?;
    if step.step_id.trim() != "synthesize" {
        return None;
    }

    let implement_output = load_step_raw_output(state, run, "implement").unwrap_or_default();
    let scorecard_fields = parse_scorecard_fields(
        result
            .raw_output
            .as_deref()
            .unwrap_or(result.merged_output.as_str()),
    );
    let notes = first_scorecard_note(
        &scorecard_fields,
        &[
            "notes",
            "note",
            "handoff_summary",
            "summary",
            "residual_risk",
            "risk",
        ],
    );
    let verifier_ready = parse_bool_like(
        scorecard_fields
            .get("verification_ready")
            .map(String::as_str),
    )
    .unwrap_or_else(|| {
        parent_playbook_coding_scorecard(run)
            .map(|scorecard| scorecard.verdict == "passed")
            .unwrap_or(false)
    });
    let fallback_status = if result.success {
        if verifier_ready {
            "ready"
        } else {
            "needs_attention"
        }
    } else {
        "blocked"
    };

    Some(PatchSynthesisSummary {
        status: normalize_patch_synthesis_status(
            scorecard_fields.get("status").map(String::as_str),
            fallback_status,
        ),
        touched_file_count: scorecard_fields
            .get("touched_file_count")
            .and_then(|value| value.parse::<u32>().ok())
            .unwrap_or_else(|| count_touched_files(&implement_output)),
        verification_ready: verifier_ready,
        notes,
    })
}

pub(crate) fn parent_playbook_patch_synthesis(
    run: &ParentPlaybookRun,
) -> Option<PatchSynthesisSummary> {
    run.steps
        .iter()
        .rev()
        .find_map(|step| step.patch_synthesis.clone())
}

pub(crate) fn build_computer_use_recovery_summary(
    state: &dyn StateAccess,
    run: &ParentPlaybookRun,
    playbook: &AgentPlaybookDefinition,
    step_idx: usize,
    result: &WorkerSessionResult,
) -> Option<ComputerUseRecoverySummary> {
    if run.playbook_id.trim() != "browser_postcondition_gate" {
        return None;
    }
    let step = playbook.steps.get(step_idx)?;
    if !matches!(step.step_id.trim(), "execute" | "verify") {
        return None;
    }

    let execute_output = load_step_raw_output(state, run, "execute").unwrap_or_default();
    let execute_fields = parse_scorecard_fields(&execute_output);
    let fields = parse_scorecard_fields(
        result
            .raw_output
            .as_deref()
            .unwrap_or(result.merged_output.as_str()),
    );
    let approval_state = normalize_computer_use_approval_state(
        fields
            .get("approval_state")
            .or_else(|| execute_fields.get("approval_state"))
            .map(String::as_str),
        "unknown",
    );
    let reason = first_scorecard_note(
        &fields,
        &[
            "recovery_reason",
            "reason",
            "blocker_summary",
            "blockers",
            "blocker",
            "notes",
            "note",
        ],
    )
    .or_else(|| {
        first_scorecard_note(
            &execute_fields,
            &[
                "recovery_reason",
                "reason",
                "blocker_summary",
                "blockers",
                "blocker",
                "notes",
                "note",
            ],
        )
    });
    let next_step =
        first_scorecard_note(&fields, &["next_recovery_step", "next_step", "next_check"]).or_else(
            || {
                first_scorecard_note(
                    &execute_fields,
                    &["next_recovery_step", "next_step", "next_check"],
                )
            },
        );

    Some(ComputerUseRecoverySummary {
        status: normalize_computer_use_recovery_status(
            fields
                .get("recovery_status")
                .or_else(|| execute_fields.get("recovery_status"))
                .map(String::as_str),
            if approval_state == "pending" {
                "pending_approval"
            } else if next_step.is_some() || reason.is_some() {
                "recommended"
            } else if result.success {
                "not_needed"
            } else {
                "blocked"
            },
        ),
        reason,
        next_step,
    })
}

pub(crate) fn parent_playbook_computer_use_recovery(
    run: &ParentPlaybookRun,
) -> Option<ComputerUseRecoverySummary> {
    run.steps
        .iter()
        .rev()
        .find_map(|step| step.computer_use_recovery.clone())
}
