use super::*;

#[derive(Debug, Clone)]
pub(crate) struct FinalWebCompletionFacts {
    pub selected_source_urls: Vec<String>,
    pub local_business_targets: Vec<String>,
    pub matched_local_business_targets: Vec<String>,
    pub local_business_source_urls: Vec<String>,
    pub observed_story_slots: usize,
    pub story_slot_floor_met: bool,
    pub story_citation_floor_met: bool,
    pub comparison_required: bool,
    pub comparison_ready: bool,
    pub single_snapshot_metric_grounding: bool,
}

pub(crate) fn final_web_completion_facts(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
) -> FinalWebCompletionFacts {
    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let locality_scope = explicit_query_scope_hint(&query_contract).or_else(|| {
        retrieval_contract_requires_runtime_locality(retrieval_contract, &query_contract)
            .then(|| effective_locality_scope_hint(None))
            .flatten()
    });
    let headline_collection_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, &query_contract);
    let required_story_floor =
        retrieval_contract_required_story_count(retrieval_contract, &query_contract).max(1);
    let min_sources_required = pending.min_sources.max(1) as usize;
    let local_business_entity_floor_required =
        retrieval_contract_entity_diversity_required(retrieval_contract, &query_contract);
    let local_business_targets = if local_business_entity_floor_required {
        merged_local_business_target_names(
            &pending.attempted_urls,
            &pending.successful_reads,
            locality_scope.as_deref(),
            required_story_floor.max(min_sources_required),
        )
    } else {
        Vec::new()
    };
    let matched_local_business_targets = if local_business_targets.is_empty() {
        Vec::new()
    } else {
        matched_local_business_target_names(
            &local_business_targets,
            &pending.successful_reads,
            locality_scope.as_deref(),
        )
    };
    let local_business_selected_sources = if local_business_targets.is_empty() {
        Vec::new()
    } else {
        selected_local_business_target_sources(
            &query_contract,
            &local_business_targets,
            &pending.successful_reads,
            locality_scope.as_deref(),
            required_story_floor.max(min_sources_required),
        )
    };
    let selected_source_urls =
        if local_business_entity_floor_required && local_business_selected_sources.is_empty() {
            Vec::new()
        } else if local_business_selected_sources.is_empty() {
            if headline_collection_mode {
                pending
                    .successful_reads
                    .iter()
                    .filter(|source| headline_source_is_actionable(source))
                    .map(|source| source.url.clone())
                    .collect::<Vec<_>>()
            } else {
                pending
                    .successful_reads
                    .iter()
                    .map(|source| source.url.clone())
                    .collect::<Vec<_>>()
            }
        } else {
            local_business_selected_sources
                .iter()
                .map(|source| source.url.clone())
                .collect::<Vec<_>>()
        };

    let final_draft = build_deterministic_story_draft(pending, reason);
    let required_citations =
        retrieval_contract_required_citations_per_story(retrieval_contract, &query_contract).max(1);
    let (headline_actionable_sources_observed, headline_actionable_domains_observed) =
        if headline_collection_mode {
            headline_actionable_source_inventory(&pending.successful_reads)
        } else {
            (0, 0)
        };
    let observed_story_slots = if headline_collection_mode {
        headline_actionable_sources_observed.min(required_story_floor)
    } else {
        final_draft.stories.len().min(required_story_floor)
    };
    let story_slot_floor_met = if headline_collection_mode {
        headline_actionable_sources_observed >= required_story_floor
            && headline_actionable_domains_observed >= required_story_floor
    } else {
        observed_story_slots >= required_story_floor
    };
    let story_citation_floor_met =
        final_draft
            .stories
            .iter()
            .take(required_story_floor)
            .all(|story| {
                story
                    .citation_ids
                    .iter()
                    .filter_map(|citation_id| final_draft.citations_by_id.get(citation_id))
                    .map(|citation| citation.url.trim())
                    .filter(|url: &&str| !url.is_empty())
                    .collect::<BTreeSet<_>>()
                    .len()
                    >= required_citations
            });
    let comparison_required =
        retrieval_contract_requests_comparison(retrieval_contract, &query_contract)
            && required_story_floor > 1;
    let comparison_ready = !comparison_required || story_slot_floor_met;
    let single_snapshot_metric_grounding =
        retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query_contract)
            && single_snapshot_has_metric_grounding(pending);

    FinalWebCompletionFacts {
        selected_source_urls,
        local_business_targets,
        matched_local_business_targets,
        local_business_source_urls: local_business_selected_sources
            .iter()
            .map(|source| source.url.clone())
            .collect(),
        observed_story_slots,
        story_slot_floor_met,
        story_citation_floor_met,
        comparison_required,
        comparison_ready,
        single_snapshot_metric_grounding,
    }
}

pub(crate) fn append_final_web_completion_receipts(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
    verification_checks: &mut Vec<String>,
) {
    let facts = final_web_completion_facts(pending, reason);

    if !facts.selected_source_urls.is_empty() {
        verification_checks.push(format!(
            "web_final_selected_source_url_values={}",
            facts.selected_source_urls.join(" | ")
        ));
    }
    if !facts.local_business_targets.is_empty() {
        verification_checks.push(format!(
            "web_final_local_business_entity_targets={}",
            facts.local_business_targets.join(" | ")
        ));
    }
    if !facts.matched_local_business_targets.is_empty() {
        verification_checks.push(format!(
            "web_final_local_business_entity_matched={}",
            facts.matched_local_business_targets.join(" | ")
        ));
    }
    if !facts.local_business_source_urls.is_empty() {
        verification_checks.push(format!(
            "web_final_local_business_entity_source_values={}",
            facts.local_business_source_urls.join(" | ")
        ));
    }
    verification_checks.push(format!(
        "web_final_story_slots_observed={}",
        facts.observed_story_slots
    ));
    verification_checks.push(format!(
        "web_final_story_slot_floor_met={}",
        facts.story_slot_floor_met
    ));
    verification_checks.push(format!(
        "web_final_story_citation_floor_met={}",
        facts.story_citation_floor_met
    ));
    verification_checks.push(format!(
        "web_final_comparison_required={}",
        facts.comparison_required
    ));
    verification_checks.push(format!(
        "web_final_comparison_ready={}",
        facts.comparison_ready
    ));
    verification_checks.push(format!(
        "web_final_single_snapshot_metric_grounding={}",
        facts.single_snapshot_metric_grounding
    ));
}

pub(crate) fn remaining_pending_web_candidates(pending: &PendingSearchCompletion) -> usize {
    let attempted: BTreeSet<String> = pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect();
    pending_candidate_inventory(pending)
        .iter()
        .map(|value| value.trim())
        .filter(|value| !value.is_empty() && !attempted.contains(*value))
        .count()
}

pub(crate) fn single_snapshot_has_metric_grounding(pending: &PendingSearchCompletion) -> bool {
    pending.successful_reads.iter().any(|source| {
        let observed_text = format!(
            "{} {}",
            source.title.as_deref().unwrap_or_default(),
            source.excerpt
        );
        contains_current_condition_metric_signal(&observed_text)
    })
}

pub(crate) fn single_snapshot_has_viable_followup_candidate(
    pending: &PendingSearchCompletion,
    query_contract: &str,
) -> bool {
    let projection =
        build_query_constraint_projection(query_contract, 1, &pending.candidate_source_hints);
    let envelope_constraints = &projection.constraints;
    let envelope_policy = ResolutionPolicy::default();
    let attempted_urls = pending
        .attempted_urls
        .iter()
        .chain(pending.blocked_urls.iter())
        .chain(pending.successful_reads.iter().map(|source| &source.url))
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .collect::<BTreeSet<_>>();

    pending_candidate_inventory(pending)
        .iter()
        .any(|candidate| {
            let trimmed = candidate.trim();
            if trimmed.is_empty() || attempted_urls.contains(trimmed) {
                return false;
            }
            let hint = hint_for_url(pending, trimmed);
            let title = hint
                .and_then(|entry| entry.title.as_deref())
                .unwrap_or_default();
            let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
            let compatibility = candidate_constraint_compatibility(
                envelope_constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                title,
                excerpt,
            );
            if projection.enforce_grounded_compatibility()
                && !compatibility_passes_projection(&projection, &compatibility)
            {
                return false;
            }
            if title.trim().is_empty() && excerpt.trim().is_empty() {
                return false;
            }
            let envelope_score = single_snapshot_candidate_envelope_score(
                envelope_constraints,
                envelope_policy,
                trimmed,
                title,
                excerpt,
            );
            let resolves_constraint =
                envelope_score_resolves_constraint(envelope_constraints, &envelope_score);
            if projection.has_constraint_objective() {
                resolves_constraint
            } else {
                resolves_constraint || compatibility_passes_projection(&projection, &compatibility)
            }
        })
}

pub(crate) fn single_snapshot_probe_budget_allows_followup(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> bool {
    if pending.deadline_ms == 0 {
        return true;
    }
    pending.deadline_ms.saturating_sub(now_ms) >= SINGLE_SNAPSHOT_MIN_REMAINING_BUDGET_MS_FOR_PROBE
}

pub(crate) fn single_snapshot_additional_probe_attempt_count(
    pending: &PendingSearchCompletion,
) -> usize {
    let observed_search_attempts = pending
        .attempted_urls
        .iter()
        .filter(|url| {
            let trimmed = url.trim();
            !trimmed.is_empty() && is_search_hub_url(trimmed)
        })
        .count();
    let baseline_search_attempt_missing_from_attempts = if is_search_hub_url(&pending.url) {
        let pending_search_url = pending.url.trim();
        !pending_search_url.is_empty()
            && !pending.attempted_urls.iter().any(|url| {
                let trimmed = url.trim();
                !trimmed.is_empty() && url_structurally_equivalent(trimmed, pending_search_url)
            })
    } else {
        false
    };
    let total_search_attempts = observed_search_attempts
        .saturating_add(usize::from(baseline_search_attempt_missing_from_attempts));
    let probe_query_delta = usize::from({
        let query = pending.query.trim();
        let query_contract = pending.query_contract.trim();
        total_search_attempts == 0
            && !query.is_empty()
            && !query_contract.is_empty()
            && !query.eq_ignore_ascii_case(query_contract)
    });
    total_search_attempts
        .saturating_sub(1)
        .saturating_add(probe_query_delta)
}

pub(crate) fn web_pipeline_grounded_probe_attempt_limit(
    pending: &PendingSearchCompletion,
) -> usize {
    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let required_distinct_source_floor =
        retrieval_contract_required_distinct_citations(retrieval_contract, &query_contract);
    required_distinct_source_floor
        .max(pending.min_sources.max(1) as usize)
        .max(1)
        .saturating_sub(1)
        .clamp(1, WEB_PIPELINE_CONSTRAINT_SEARCH_LIMIT_MAX as usize)
}

pub(crate) fn web_pipeline_grounded_probe_attempt_available(
    pending: &PendingSearchCompletion,
) -> bool {
    single_snapshot_additional_probe_attempt_count(pending)
        < web_pipeline_grounded_probe_attempt_limit(pending)
}

pub(crate) fn single_snapshot_requires_current_metric_observation_contract(
    pending: &PendingSearchCompletion,
) -> bool {
    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    if !retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query_contract) {
        return false;
    }
    let projection = build_query_constraint_projection(
        &query_contract,
        pending.min_sources.max(1),
        &pending.candidate_source_hints,
    );
    let has_metric_objective = !projection.constraints.required_facets.is_empty()
        || !projection.query_facets.metric_schema.axis_hits.is_empty()
        || (projection.query_facets.time_sensitive_public_fact
            && projection.query_facets.locality_sensitive_public_fact);
    let requires_current_observation = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        || projection.query_facets.time_sensitive_public_fact
        || retrieval_contract
            .map(|contract| contract.currentness_required)
            .unwrap_or(false);
    has_metric_objective && requires_current_observation
}

pub(crate) fn web_pipeline_requires_metric_probe_followup(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> bool {
    if !single_snapshot_requires_current_metric_observation_contract(pending) {
        return false;
    }
    let query_contract = synthesis_query_contract(pending);
    let min_sources = pending.min_sources.max(1) as usize;
    if pending.successful_reads.len() < min_sources {
        return false;
    }
    if single_snapshot_has_metric_grounding(pending) {
        return false;
    }
    if single_snapshot_additional_probe_attempt_count(pending)
        >= SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES
    {
        return false;
    }
    if !single_snapshot_probe_budget_allows_followup(pending, now_ms) {
        return false;
    }
    if single_snapshot_has_viable_followup_candidate(pending, &query_contract) {
        return true;
    }
    // Pre-emit quality gate: allow one deterministic recovery probe even when
    // candidate inventory is exhausted, so the pipeline can self-correct
    // missing current-observation metrics before final reply emission.
    true
}

pub(crate) fn web_pipeline_completion_reason(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> Option<WebPipelineCompletionReason> {
    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    let required_distinct_source_floor =
        retrieval_contract_required_distinct_citations(retrieval_contract, &query_contract);

    let single_snapshot_mode =
        retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query_contract);
    let headline_collection_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, &query_contract);
    let required_story_floor =
        retrieval_contract_required_story_count(retrieval_contract, &query_contract).max(1);
    let (headline_actionable_sources_observed, headline_actionable_domains_observed) =
        if headline_collection_mode {
            headline_actionable_source_inventory(&pending.successful_reads)
        } else {
            (0, 0)
        };
    let story_floor_met = !headline_collection_mode
        || (headline_actionable_sources_observed >= required_story_floor
            && headline_actionable_domains_observed >= required_story_floor);
    let query_facets = analyze_query_facets(&query_contract);
    let remaining_candidates = remaining_pending_web_candidates(pending);
    let has_viable_followup_candidate =
        single_snapshot_has_viable_followup_candidate(pending, &query_contract);
    let min_sources = pending.min_sources.max(1) as usize;
    let locality_scope = explicit_query_scope_hint(&query_contract).or_else(|| {
        retrieval_contract_requires_runtime_locality(retrieval_contract, &query_contract)
            .then(|| effective_locality_scope_hint(None))
            .flatten()
    });
    let local_business_entity_floor_required =
        retrieval_contract_entity_diversity_required(retrieval_contract, &query_contract);
    let local_business_targets = if local_business_entity_floor_required {
        merged_local_business_target_names(
            &pending.attempted_urls,
            &pending.successful_reads,
            locality_scope.as_deref(),
            required_story_floor.max(min_sources),
        )
    } else {
        Vec::new()
    };
    let matched_local_business_targets = if local_business_targets.is_empty() {
        Vec::new()
    } else {
        matched_local_business_target_names(
            &local_business_targets,
            &pending.successful_reads,
            locality_scope.as_deref(),
        )
    };
    let local_business_entity_floor_met = !local_business_entity_floor_required
        || (!local_business_targets.is_empty()
            && matched_local_business_targets.len() >= required_story_floor.max(min_sources));
    let grounded_sources = grounded_source_evidence_count(pending);
    let required_grounded_source_floor = required_distinct_source_floor.max(min_sources);
    let grounded_floor_met = if headline_collection_mode {
        headline_actionable_sources_observed >= min_sources
            && headline_actionable_domains_observed >= min_sources
    } else if single_snapshot_mode || !query_facets.grounded_external_required {
        pending.successful_reads.len() >= min_sources
    } else {
        grounded_sources >= required_grounded_source_floor && local_business_entity_floor_met
    };

    if single_snapshot_mode
        && pending.successful_reads.len() >= 1
        && pending.successful_reads.len() < min_sources
        && grounded_floor_met
        && !single_snapshot_has_metric_grounding(pending)
        && !has_viable_followup_candidate
    {
        return Some(WebPipelineCompletionReason::ExhaustedCandidates);
    }

    if grounded_floor_met {
        if headline_collection_mode && !story_floor_met {
            let grounded_probe_budget_allows = if pending.deadline_ms == 0 {
                true
            } else {
                pending.deadline_ms.saturating_sub(now_ms)
                    >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE
            };
            if web_pipeline_grounded_probe_attempt_available(pending)
                && grounded_probe_budget_allows
            {
                return None;
            }
            return Some(WebPipelineCompletionReason::ExhaustedCandidates);
        }
        if single_snapshot_mode && web_pipeline_requires_metric_probe_followup(pending, now_ms) {
            return None;
        }
        if single_snapshot_mode && !single_snapshot_has_metric_grounding(pending) {
            let post_probe_attempt_available =
                single_snapshot_additional_probe_attempt_count(pending) > 0;
            if post_probe_attempt_available
                && remaining_candidates > 0
                && next_pending_web_candidate(pending).is_some()
            {
                return None;
            }
            return Some(WebPipelineCompletionReason::ExhaustedCandidates);
        }
        return Some(WebPipelineCompletionReason::MinSourcesReached);
    }
    if pending.deadline_ms > 0 && now_ms >= pending.deadline_ms {
        return Some(WebPipelineCompletionReason::DeadlineReached);
    }
    if remaining_candidates == 0 {
        let grounded_probe_budget_allows = if pending.deadline_ms == 0 {
            true
        } else {
            pending.deadline_ms.saturating_sub(now_ms)
                >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE
        };
        let grounded_probe_recovery = !single_snapshot_mode
            && query_facets.grounded_external_required
            && !grounded_floor_met
            && web_pipeline_grounded_probe_attempt_available(pending)
            && grounded_probe_budget_allows;
        if grounded_probe_recovery {
            return None;
        }
        // Keep the loop alive for one bounded probe when the citation/source floor
        // is still unmet in single-snapshot mode and budget allows recovery.
        if single_snapshot_mode
            && !grounded_floor_met
            && single_snapshot_additional_probe_attempt_count(pending)
                < SINGLE_SNAPSHOT_MAX_ADDITIONAL_PROBE_SOURCES
            && single_snapshot_probe_budget_allows_followup(pending, now_ms)
        {
            return None;
        }
        return Some(WebPipelineCompletionReason::ExhaustedCandidates);
    }
    None
}

pub(crate) fn queue_web_read_from_pipeline(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    url: &str,
) -> Result<bool, TransactionError> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    let params = serde_jcs::to_vec(&json!({ "url": trimmed }))
        .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target: ActionTarget::WebRetrieve,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1,
    };

    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return Ok(false);
    }

    agent_state.execution_queue.insert(0, request);
    Ok(true)
}

pub(crate) fn queue_web_search_from_pipeline(
    agent_state: &mut AgentState,
    session_id: [u8; 32],
    query: &str,
    query_contract: Option<&str>,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    limit: u32,
) -> Result<bool, TransactionError> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        return Ok(false);
    }
    let params = serde_jcs::to_vec(&json!({
        "query": trimmed,
        "query_contract": query_contract
            .map(str::trim)
            .filter(|value| !value.is_empty()),
        "retrieval_contract": retrieval_contract,
        "limit": limit.max(1),
    }))
    .map_err(|e| TransactionError::Serialization(e.to_string()))?;
    let request = ActionRequest {
        target: ActionTarget::WebRetrieve,
        params,
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: Some(session_id),
            window_id: None,
        },
        nonce: agent_state.step_count as u64 + agent_state.execution_queue.len() as u64 + 1,
    };
    let duplicate = agent_state
        .execution_queue
        .iter()
        .any(|queued| queued.target == request.target && queued.params == request.params);
    if duplicate {
        return Ok(false);
    }
    agent_state.execution_queue.insert(0, request);
    Ok(true)
}

pub(crate) fn is_human_challenge_error(error: &str) -> bool {
    let lower = error.to_ascii_lowercase();
    lower.contains("error_class=humanchallengerequired")
        || lower.contains("recaptcha")
        || lower.contains("human verification")
        || lower.contains("verify you are human")
        || lower.contains("i'm not a robot")
        || lower.contains("i am not a robot")
}
