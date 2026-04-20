use super::*;

#[allow(unused_imports)]
pub(crate) use super::facts::{
    final_web_completion_contract_ready, final_web_completion_facts,
    final_web_completion_facts_with_rendered_summary, select_final_web_summary_from_candidates,
    FinalWebCompletionFacts, FinalWebSummaryCandidate, FinalWebSummaryCandidateEvaluation,
    FinalWebSummarySelection,
};
#[cfg(test)]
use super::facts::{
    local_business_menu_inventory_items_from_excerpt, rendered_summary_citation_urls,
};

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

fn single_snapshot_has_explicit_price_quote_grounding(pending: &PendingSearchCompletion) -> bool {
    let query_contract = synthesis_query_contract(pending);
    if !analyze_query_facets(&query_contract)
        .metric_schema
        .axis_hits
        .contains(&MetricAxis::Price)
    {
        return false;
    }

    pending.successful_reads.iter().any(|source| {
        let observed_text = format!(
            "{} {}",
            source.title.as_deref().unwrap_or_default(),
            source.excerpt
        );
        has_price_quote_payload(&observed_text)
    })
}

pub(crate) fn single_snapshot_has_subject_identity_grounding(
    pending: &PendingSearchCompletion,
) -> bool {
    pending.successful_reads.iter().any(|source| {
        let observed_text = format!(
            "{} {}",
            source.title.as_deref().unwrap_or_default(),
            source.excerpt
        );
        first_subject_currentness_sentence(&observed_text).is_some()
    })
}

pub(crate) fn single_snapshot_has_viable_followup_candidate(
    pending: &PendingSearchCompletion,
    query_contract: &str,
) -> bool {
    let required_story_floor = retrieval_contract_required_story_count(
        pending.retrieval_contract.as_ref(),
        query_contract,
    )
    .max(1);
    if story_completion_contract_ready(pending, required_story_floor) {
        return false;
    }
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

fn grounded_probe_query_available(
    pending: &PendingSearchCompletion,
    locality_scope: Option<&str>,
) -> bool {
    let query_contract = synthesis_query_contract(pending);
    let local_business_menu_surface_recovery = query_requires_local_business_menu_surface(
        &query_contract,
        pending.retrieval_contract.as_ref(),
        locality_scope,
    );
    let document_briefing_authority_recovery_exhausted = pending.candidate_source_hints.is_empty()
        && !pending.successful_reads.is_empty()
        && query_prefers_document_briefing_layout(&query_contract)
        && !query_requests_comparison(&query_contract)
        && pending.successful_reads.iter().any(|source| {
            source_has_document_authority(
                &query_contract,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            )
        });
    if document_briefing_authority_recovery_exhausted {
        return false;
    }
    let prior_query_owned = if !local_business_menu_surface_recovery
        && pending.candidate_source_hints.is_empty()
        && !pending.successful_reads.is_empty()
    {
        constraint_grounded_search_query_with_contract_and_hints_and_locality_hint(
            &query_contract,
            pending.retrieval_contract.as_ref(),
            pending.min_sources,
            &pending.candidate_source_hints,
            locality_scope,
        )
    } else {
        String::new()
    };
    let prior_query = if !prior_query_owned.trim().is_empty() {
        prior_query_owned.trim()
    } else if pending.query.trim().is_empty() {
        query_contract.trim()
    } else {
        pending.query.trim()
    };
    constraint_grounded_probe_query_with_contract_and_hints_and_locality_hint(
        &query_contract,
        pending.retrieval_contract.as_ref(),
        pending.min_sources,
        &pending.candidate_source_hints,
        prior_query,
        locality_scope,
    )
    .is_some()
}

pub(crate) fn single_snapshot_requires_current_metric_observation_contract(
    pending: &PendingSearchCompletion,
) -> bool {
    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    if !retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query_contract) {
        return false;
    }
    if analyze_query_facets(&query_contract).time_sensitive_public_fact
        && query_requires_subject_currentness_identity(&query_contract)
    {
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

pub(crate) fn single_snapshot_requires_subject_identity_contract(
    pending: &PendingSearchCompletion,
) -> bool {
    let query_contract = synthesis_query_contract(pending);
    let retrieval_contract = pending.retrieval_contract.as_ref();
    retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &query_contract)
        && analyze_query_facets(&query_contract).time_sensitive_public_fact
        && query_requires_subject_currentness_identity(&query_contract)
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

pub(crate) fn web_pipeline_requires_subject_identity_probe_followup(
    pending: &PendingSearchCompletion,
    now_ms: u64,
) -> bool {
    if !single_snapshot_requires_subject_identity_contract(pending) {
        return false;
    }
    let query_contract = synthesis_query_contract(pending);
    let min_sources = pending.min_sources.max(1) as usize;
    if pending.successful_reads.len() < min_sources {
        return false;
    }
    if single_snapshot_has_subject_identity_grounding(pending) {
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
    true
}

pub(crate) fn story_completion_contract_ready(
    pending: &PendingSearchCompletion,
    required_story_floor: usize,
) -> bool {
    if required_story_floor == 0 {
        return true;
    }
    let facts = final_web_completion_facts(pending, WebPipelineCompletionReason::MinSourcesReached);
    if facts.briefing_layout_profile == "single_snapshot" {
        return facts.single_snapshot_metric_grounding
            && facts.briefing_selected_source_quality_floor_met
            && facts.briefing_selected_source_identifier_coverage_floor_met
            && facts.briefing_primary_authority_source_floor_met
            && facts.briefing_citation_read_backing_floor_met
            && facts.story_slot_floor_met
            && !facts.selected_source_urls.is_empty()
            && (!facts.comparison_required || facts.comparison_ready);
    }
    if facts.briefing_document_layout_met {
        return facts.briefing_selected_source_quality_floor_met
            && facts.briefing_selected_source_identifier_coverage_floor_met
            && facts.briefing_required_section_floor_met
            && facts.briefing_query_grounding_floor_met
            && facts.briefing_standard_identifier_floor_met
            && facts.briefing_authority_standard_identifier_floor_met
            && facts.briefing_summary_inventory_floor_met
            && facts.briefing_narrative_aggregation_floor_met
            && facts.briefing_evidence_block_floor_met
            && facts.briefing_primary_authority_source_floor_met
            && facts.briefing_citation_read_backing_floor_met
            && facts.briefing_temporal_anchor_floor_met
            && facts.briefing_postamble_floor_met
            && (!facts.comparison_required || facts.comparison_ready);
    }
    facts.story_slot_floor_met
        && facts.story_citation_floor_met
        && facts.local_business_menu_surface_floor_met
        && facts.local_business_menu_inventory_floor_met
        && facts.observed_story_slots >= required_story_floor
        && (!facts.comparison_required || facts.comparison_ready)
}

pub(crate) fn web_pipeline_completion_terminalization_allowed(
    pending: &PendingSearchCompletion,
    reason: WebPipelineCompletionReason,
    queued_web_reads: usize,
) -> bool {
    if queued_web_reads == 0 || !matches!(reason, WebPipelineCompletionReason::MinSourcesReached) {
        return true;
    }

    let query_contract = synthesis_query_contract(pending);
    let locality_hint = explicit_query_scope_hint(&query_contract).or_else(|| {
        retrieval_contract_requires_runtime_locality(
            pending.retrieval_contract.as_ref(),
            &query_contract,
        )
        .then(|| effective_locality_scope_hint(None))
        .flatten()
    });
    if query_requires_local_business_menu_surface(
        &query_contract,
        pending.retrieval_contract.as_ref(),
        locality_hint.as_deref(),
    ) {
        return false;
    }
    if !matches!(
        synthesis_layout_profile(pending.retrieval_contract.as_ref(), &query_contract),
        SynthesisLayoutProfile::DocumentBriefing
    ) {
        return true;
    }

    next_pending_web_candidate(pending).is_none()
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
    let single_snapshot_metric_required =
        single_snapshot_requires_current_metric_observation_contract(pending);
    let single_snapshot_subject_identity_required =
        single_snapshot_requires_subject_identity_contract(pending);
    let headline_collection_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, &query_contract);
    let layout_profile = synthesis_layout_profile(retrieval_contract, &query_contract);
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
    let next_viable_candidate_available = next_pending_web_candidate(pending).is_some();
    let candidate_inventory_exhausted =
        remaining_candidates == 0 || !next_viable_candidate_available;
    let min_sources = pending.min_sources.max(1) as usize;
    let locality_scope = explicit_query_scope_hint(&query_contract).or_else(|| {
        retrieval_contract_requires_runtime_locality(retrieval_contract, &query_contract)
            .then(|| effective_locality_scope_hint(None))
            .flatten()
    });
    let grounded_probe_query_available =
        grounded_probe_query_available(pending, locality_scope.as_deref());
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
        && single_snapshot_metric_required
        && !single_snapshot_has_metric_grounding(pending)
        && !has_viable_followup_candidate
    {
        return Some(WebPipelineCompletionReason::ExhaustedCandidates);
    }

    if grounded_floor_met {
        if single_snapshot_mode
            && candidate_inventory_exhausted
            && pending.successful_reads.len() >= min_sources
            && single_snapshot_metric_required
            && single_snapshot_has_metric_grounding(pending)
            && single_snapshot_has_explicit_price_quote_grounding(pending)
        {
            return Some(WebPipelineCompletionReason::MinSourcesReached);
        }
        if headline_collection_mode && !story_floor_met {
            let grounded_probe_budget_allows = if pending.deadline_ms == 0 {
                true
            } else {
                pending.deadline_ms.saturating_sub(now_ms)
                    >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE
            };
            if web_pipeline_grounded_probe_attempt_available(pending)
                && grounded_probe_budget_allows
                && grounded_probe_query_available
            {
                return None;
            }
            return Some(WebPipelineCompletionReason::ExhaustedCandidates);
        }
        if matches!(layout_profile, SynthesisLayoutProfile::DocumentBriefing)
            && !story_completion_contract_ready(pending, required_story_floor)
        {
            let grounded_probe_budget_allows = if pending.deadline_ms == 0 {
                true
            } else {
                pending.deadline_ms.saturating_sub(now_ms)
                    >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE
            };
            if web_pipeline_grounded_probe_attempt_available(pending)
                && grounded_probe_budget_allows
                && grounded_probe_query_available
            {
                return None;
            }
            if !candidate_inventory_exhausted {
                return None;
            }
            return Some(WebPipelineCompletionReason::ExhaustedCandidates);
        }
        if single_snapshot_mode && web_pipeline_requires_metric_probe_followup(pending, now_ms) {
            return None;
        }
        if single_snapshot_mode
            && single_snapshot_subject_identity_required
            && web_pipeline_requires_subject_identity_probe_followup(pending, now_ms)
        {
            return None;
        }
        if single_snapshot_mode
            && single_snapshot_metric_required
            && !single_snapshot_has_metric_grounding(pending)
        {
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
        if single_snapshot_mode
            && single_snapshot_subject_identity_required
            && !single_snapshot_has_subject_identity_grounding(pending)
        {
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
        if single_snapshot_mode {
            if !story_completion_contract_ready(pending, required_story_floor) {
                let grounded_probe_budget_allows = if pending.deadline_ms == 0 {
                    true
                } else {
                    pending.deadline_ms.saturating_sub(now_ms)
                        >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE
                };
                if !candidate_inventory_exhausted {
                    return None;
                }
                if web_pipeline_grounded_probe_attempt_available(pending)
                    && grounded_probe_budget_allows
                    && grounded_probe_query_available
                {
                    return None;
                }
                return Some(WebPipelineCompletionReason::ExhaustedCandidates);
            }
        }
        if !single_snapshot_mode
            && !headline_collection_mode
            && !story_completion_contract_ready(pending, required_story_floor)
        {
            let grounded_probe_budget_allows = if pending.deadline_ms == 0 {
                true
            } else {
                pending.deadline_ms.saturating_sub(now_ms)
                    >= WEB_PIPELINE_MIN_REMAINING_BUDGET_MS_FOR_SEARCH_PROBE
            };
            if !candidate_inventory_exhausted {
                return None;
            }
            if web_pipeline_grounded_probe_attempt_available(pending)
                && grounded_probe_budget_allows
                && grounded_probe_query_available
            {
                return None;
            }
            return Some(WebPipelineCompletionReason::ExhaustedCandidates);
        }
        return Some(WebPipelineCompletionReason::MinSourcesReached);
    }
    if !single_snapshot_mode
        && pending.successful_reads.len() >= min_sources
        && story_completion_contract_ready(pending, required_story_floor)
    {
        return Some(WebPipelineCompletionReason::MinSourcesReached);
    }
    if pending.deadline_ms > 0 && now_ms >= pending.deadline_ms {
        return Some(WebPipelineCompletionReason::DeadlineReached);
    }
    if candidate_inventory_exhausted {
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
            && grounded_probe_budget_allows
            && grounded_probe_query_available;
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

#[cfg(test)]
#[path = "completion/tests.rs"]
mod tests;
