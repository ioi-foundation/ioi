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
mod tests {
    use ioi_types::app::agentic::WebRetrievalContract;

    use super::*;

    fn nist_briefing_contract() -> ioi_types::app::agentic::WebRetrievalContract {
        crate::agentic::web::derive_web_retrieval_contract(
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.",
            None,
        )
        .expect("retrieval contract")
    }

    fn retained_like_nist_briefing_query_contract() -> &'static str {
        "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks."
    }

    fn retained_like_nist_briefing_contract() -> ioi_types::app::agentic::WebRetrievalContract {
        crate::agentic::web::derive_web_retrieval_contract(
            retained_like_nist_briefing_query_contract(),
            None,
        )
        .expect("retrieval contract")
    }

    fn retained_like_nist_briefing_pending() -> PendingSearchCompletion {
        PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract: retained_like_nist_briefing_query_contract().to_string(),
            retrieval_contract: Some(retained_like_nist_briefing_contract()),
            url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_775_102_589_241,
            deadline_ms: 1_775_102_649_241,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                    title: Some(
                        "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                            .to_string(),
                    ),
                    excerpt:
                        "IR 8413 Update 1 is the status report on the NIST post-quantum cryptography standardization process."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
                    title: Some(
                        "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                            .to_string(),
                    ),
                    excerpt:
                        "IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved"
                        .to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | CSRC"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST finalized FIPS 203, FIPS 204, and FIPS 205 as its first post-quantum cryptography standards."
                            .to_string(),
                },
            ],
            min_sources: 2,
        }
    }

    fn weather_snapshot_contract() -> ioi_types::app::agentic::WebRetrievalContract {
        crate::agentic::web::derive_web_retrieval_contract(
            "What's the weather like right now in Anderson, SC?",
            None,
        )
        .expect("retrieval contract")
    }

    fn weather_snapshot_pending() -> PendingSearchCompletion {
        PendingSearchCompletion {
            query: "What's the weather like right now in Anderson, SC?".to_string(),
            query_contract: "What's the weather like right now in Anderson, SC?".to_string(),
            retrieval_contract: Some(weather_snapshot_contract()),
            url: "https://forecast.weather.gov/MapClick.php?lat=34.5186&lon=-82.6458&unit=0&lg=english&FcstType=graphical".to_string(),
            started_step: 1,
            started_at_ms: 1_773_235_143_000,
            deadline_ms: 1_773_235_203_000,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://forecast.weather.gov/MapClick.php?lat=34.5186&lon=-82.6458&unit=0&lg=english&FcstType=graphical".to_string(),
                title: Some(
                    "Anderson, Anderson County Airport (KAND) current conditions".to_string(),
                ),
                excerpt: "Current conditions at Anderson, Anderson County Airport (KAND); Fair; temperature 65°F (18°C); Humidity 93%; Wind Speed SW 3 mph; Barometer 30.06 in (1017.2 mb); Visibility 10.00 mi; Last update 11 Mar 8:56 am EDT.".to_string(),
            }],
            min_sources: 1,
        }
    }

    fn openai_api_pricing_snapshot_pending() -> PendingSearchCompletion {
        let query = "What is the latest OpenAI API pricing?";
        let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
            .expect("retrieval contract");
        PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract: Some(retrieval_contract),
            url: "https://duckduckgo.com/html/?q=openai+api+pricing".to_string(),
            started_step: 1,
            started_at_ms: 1_776_227_441_000,
            deadline_ms: 1_776_227_561_000,
            candidate_urls: vec![
                "https://openai.com/api/pricing/".to_string(),
                "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services"
                    .to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://openai.com/api/pricing/".to_string(),
                    title: Some("API Pricing | OpenAI API".to_string()),
                    excerpt: "Image: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services".to_string(),
                    title: Some("Making Sense of the OpenAI API's Pricing and Services".to_string()),
                    excerpt: "A guide to understanding the OpenAI API's pricing, including token costs and service tiers.".to_string(),
                },
            ],
            attempted_urls: vec![
                "https://duckduckgo.com/html/?q=openai+api+pricing".to_string(),
                "https://openai.com/api/pricing/".to_string(),
            ],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://openai.com/api/pricing/".to_string(),
                title: Some("API Pricing | OpenAI API".to_string()),
                excerpt: "Image: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs".to_string(),
            }],
            min_sources: 1,
        }
    }

    fn liveish_openai_api_pricing_anchor_pending() -> PendingSearchCompletion {
        let query = "What is the latest OpenAI API pricing?";
        let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
            .expect("retrieval contract");
        PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract: Some(retrieval_contract),
            url: "https://search.brave.com/search?q=openai+api+pricing".to_string(),
            started_step: 1,
            started_at_ms: 1_776_229_080_000,
            deadline_ms: 1_776_229_200_000,
            candidate_urls: vec![
                "https://openai.com/api/pricing/".to_string(),
                "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services"
                    .to_string(),
            ],
            candidate_source_hints: vec![PendingSearchReadSummary {
                url: "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services"
                    .to_string(),
                title: Some("OpenAI API Pricing & Services - A Comprehensive Guide".to_string()),
                excerpt: "Price: Input: $1.10 per 1M tokens, Cached input: $0.275 per 1M tokens, Output: $4.40 per 1M tokens.".to_string(),
            }],
            attempted_urls: vec![
                "https://search.brave.com/search?q=openai+api+pricing".to_string(),
                "https://openai.com/api/pricing/".to_string(),
            ],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://openai.com/api/pricing/".to_string(),
                title: Some("OpenAI API Pricing | OpenAI".to_string()),
                excerpt: String::new(),
            }],
            min_sources: 1,
        }
    }

    #[test]
    fn grounded_probe_query_availability_detects_non_recoverable_latest_nist_briefing_loop() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: Vec::new(),
            candidate_source_hints: Vec::new(),
            attempted_urls: vec![
                "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                    .to_string(),
            ],
            blocked_urls: Vec::new(),
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as its first finalized post-quantum cryptography standards."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt:
                        "NIST directs organizations to migrate to post-quantum encryption standards now."
                            .to_string(),
                },
            ],
            min_sources: 3,
        };

        assert!(!grounded_probe_query_available(&pending, None));
        assert_eq!(
            web_pipeline_completion_reason(&pending, 1_773_117_280_000),
            Some(WebPipelineCompletionReason::ExhaustedCandidates)
        );
    }

    #[test]
    fn story_contract_ready_terminalizes_latest_nist_briefing_when_grounded_sources_are_merged() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                            .to_string(),
                    ),
                    excerpt: "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                    title: Some(
                        "Federal Information Processing Standard (FIPS) 204".to_string(),
                    ),
                    excerpt: "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards."
                        .to_string(),
                },
            ],
            attempted_urls: vec![
                "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                    .to_string(),
            ],
            blocked_urls: vec![
                "https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans"
                    .to_string(),
            ],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards"
                            .to_string(),
                    ),
                    excerpt: "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                    title: Some(
                        "Federal Information Processing Standard (FIPS) 204".to_string(),
                    ),
                    excerpt: "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards."
                        .to_string(),
                },
            ],
            min_sources: 3,
        };

        let summary =
            synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            &summary,
        );
        assert!(facts
            .briefing_required_sections
            .iter()
            .any(|section| section == "what_happened"));
        assert!(facts
            .briefing_required_sections
            .iter()
            .any(|section| section == "key_evidence"));
        assert_eq!(facts.briefing_layout_profile, "document_briefing");
        assert!(facts.briefing_document_layout_met);
        assert!(facts.briefing_render_heading_floor_met);
        assert!(facts.briefing_rendered_required_section_label_floor_met);
        assert_eq!(facts.briefing_story_header_count, 0);
        assert!(facts.briefing_story_headers_absent);
        assert_eq!(facts.briefing_comparison_label_count, 0);
        assert!(facts.briefing_comparison_absent);
        assert!(facts.briefing_required_section_floor_met);
        assert!(facts.briefing_query_grounding_floor_met);
        assert!(facts.briefing_standard_identifier_floor_met);
        assert!(facts.briefing_authority_standard_identifier_floor_met);
        assert!(facts.briefing_summary_inventory_floor_met);
        assert!(facts.briefing_evidence_block_floor_met);
        assert!(facts.briefing_temporal_anchor_floor_met);
        assert!(facts.briefing_postamble_floor_met);
        assert!(story_completion_contract_ready(&pending, 3));
        assert_eq!(
            web_pipeline_completion_reason(&pending, 1_773_117_280_000),
            Some(WebPipelineCompletionReason::MinSourcesReached)
        );
    }

    #[test]
    fn story_contract_ready_requires_primary_authority_source_when_available_for_document_briefing()
    {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![
                "https://www.nist.gov/pqc".to_string(),
                "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards.".to_string(),
                },
            ],
            attempted_urls: vec![
                "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                    .to_string(),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.digicert.com/blog/nist-standards-for-quantum-safe-cryptography"
                        .to_string(),
                    title: Some("NIST standards for quantum-safe cryptography".to_string()),
                    excerpt: "DigiCert explains the latest NIST standards for quantum-safe cryptography.".to_string(),
                },
            ],
            min_sources: 2,
        };

        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);
        assert_eq!(facts.available_primary_authority_source_count, 1);
        assert_eq!(facts.selected_primary_authority_source_count, 0);
        assert!(!facts.briefing_primary_authority_source_floor_met);
        assert!(!story_completion_contract_ready(&pending, 1));
    }

    #[test]
    fn story_contract_ready_prefers_ir_briefing_authority_citations_over_generic_nist_policy_pages()
    {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_775_094_450_000,
            deadline_ms: 1_775_094_570_000,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
                    title: Some(
                        "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                            .to_string(),
                    ),
                    excerpt:
                        "NIST's current authoritative publication set for the post-quantum cryptography standardization process includes IR 8413."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
                    title: Some(
                        "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC"
                            .to_string(),
                    ),
                    excerpt:
                        "IR 8413 documents the authoritative NIST status report for the post-quantum cryptography standardization process."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/no-fear-act-policy".to_string(),
                    title: Some("No Fear Act Policy | NIST".to_string()),
                    excerpt:
                        "NIST publishes its No Fear Act policy information for general agency compliance."
                            .to_string(),
                },
            ],
            min_sources: 2,
        };

        let summary =
            synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            &summary,
        );

        assert!(summary.contains("current authoritative publications as IR 8413."));
        assert!(summary.contains("https://csrc.nist.gov/pubs/ir/8413/upd1/final"));
        assert!(summary.contains("https://csrc.nist.gov/pubs/ir/8413/final"));
        assert!(!summary.contains("https://www.nist.gov/no-fear-act-policy"));
        assert!(facts.briefing_summary_inventory_floor_met);
        assert!(!facts.briefing_selected_source_quality_floor_met);
        assert!(facts.briefing_selected_source_identifier_coverage_floor_met);
        assert!(facts.selected_source_urls.iter().any(|url| {
            url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/ir/8413/upd1/final")
        }));
        assert!(facts
            .selected_source_urls
            .iter()
            .any(|url| { url.eq_ignore_ascii_case("https://csrc.nist.gov/pubs/ir/8413/final") }));
        assert!(!facts
            .selected_source_urls
            .iter()
            .any(|url| { url.eq_ignore_ascii_case("https://www.nist.gov/no-fear-act-policy") }));
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn story_contract_ready_requires_menu_surface_sources_for_restaurant_menu_comparison() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let pending = PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract: Some(
                crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                    .expect("retrieval contract"),
            ),
            url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Brothers Italian Cuisine",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Coach House Restaurant",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Dolce Vita Italian Bistro and Pizzeria",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/"
                        .to_string(),
                    title: Some(
                        "Brothers Italian Cuisine, Anderson - Menu, Reviews (226), Photos (25) - Restaurantji"
                            .to_string(),
                    ),
                    excerpt: "Italian restaurant in Anderson, SC serving pizza, pasta and subs."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/"
                        .to_string(),
                    title: Some(
                        "Coach House Restaurant, Anderson - Menu, Reviews (242), Photos (52) - Restaurantji"
                            .to_string(),
                    ),
                    excerpt:
                        "Anderson steakhouse and Italian restaurant with lasagna, ravioli and house specials."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/"
                        .to_string(),
                    title: Some(
                        "Dolce Vita Italian Bistro and Pizzeria, Anderson - Menu, Reviews (278), Photos (51) - Restaurantji"
                            .to_string(),
                    ),
                    excerpt:
                        "Italian bistro in Anderson, SC with pizza, pasta, calzones and dessert."
                            .to_string(),
                },
            ],
            min_sources: 3,
        };

        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);

        assert!(facts.local_business_menu_surface_required);
        assert!(facts.local_business_menu_surface_source_urls.is_empty());
        assert!(!facts.local_business_menu_surface_floor_met);
        assert!(!story_completion_contract_ready(&pending, 3));
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn story_contract_ready_accepts_menu_surface_sources_for_restaurant_menu_comparison() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let pending = PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract: Some(
                crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                    .expect("retrieval contract"),
            ),
            url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Brothers Italian Cuisine",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Coach House Restaurant",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Dolce Vita Italian Bistro and Pizzeria",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/"
                        .to_string(),
                    title: Some("Menu".to_string()),
                    excerpt:
                        "Customers' favorites include Brothers Special Shrimp Pasta, Chef Salad, Italian Stromboli, Grilled Chicken Salad, and Meat Lovers Calzone. Menu photo gallery available with 6 images."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
                        .to_string(),
                    title: Some("Menu".to_string()),
                    excerpt:
                        "Customers' favorites include Assorted Home Made Cakes, Chicken and Dumplings, Chicken Fried Steak, Baked Greek Chicken, and Roast Beef Sandwich. Menu photo gallery available with 19 images."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/menu/"
                        .to_string(),
                    title: Some("Menu".to_string()),
                    excerpt:
                        "Customers' favorites include Margherita Pizza, Baked Ziti, Chicken Alfredo, Calzone, and Cannoli. Menu photo gallery available with 7 images."
                            .to_string(),
                },
            ],
            min_sources: 3,
        };

        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);

        assert!(facts.local_business_menu_surface_required);
        assert_eq!(facts.local_business_menu_surface_source_urls.len(), 3);
        assert!(facts.local_business_menu_surface_floor_met);
        assert_eq!(facts.local_business_menu_inventory_source_urls.len(), 3);
        assert!(facts.local_business_menu_inventory_total_item_count >= 6);
        assert!(facts.local_business_menu_inventory_floor_met);
        assert!(story_completion_contract_ready(&pending, 3));
        assert!(final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn story_contract_ready_requires_menu_inventory_for_restaurant_menu_comparison() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let pending = PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract: Some(
                crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                    .expect("retrieval contract"),
            ),
            url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Brothers Italian Cuisine",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Coach House Restaurant",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Dolce Vita Italian Bistro and Pizzeria",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/"
                        .to_string(),
                    title: Some("Menu".to_string()),
                    excerpt:
                        "View the menu, hours, phone number, address and map for Brothers Italian Cuisine."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
                        .to_string(),
                    title: Some("Menu".to_string()),
                    excerpt:
                        "View the menu, hours, phone number, address and map for Coach House Restaurant."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/dolce-vita-italian-bistro-and-pizzeria-/menu/"
                        .to_string(),
                    title: Some("Menu".to_string()),
                    excerpt:
                        "View the menu, hours, phone number, address and map for Dolce Vita Italian Bistro and Pizzeria."
                            .to_string(),
                },
            ],
            min_sources: 3,
        };

        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);

        assert!(facts.local_business_menu_surface_required);
        assert_eq!(facts.local_business_menu_surface_source_urls.len(), 3);
        assert!(facts.local_business_menu_surface_floor_met);
        assert!(facts.local_business_menu_inventory_source_urls.is_empty());
        assert_eq!(facts.local_business_menu_inventory_total_item_count, 0);
        assert!(!facts.local_business_menu_inventory_floor_met);
        assert!(!story_completion_contract_ready(&pending, 3));
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn menu_inventory_parser_accepts_canonical_inventory_intro() {
        let items = local_business_menu_inventory_items_from_excerpt(
            "Item inventory includes Organic Smoked Ham Hero Sandwich, Meatball Hero Sandwich, Gourmet Chicken Hero Sandwich, and Philly Steak & Cheese Hero Sandwich.",
        );

        assert_eq!(
            items,
            vec![
                "Organic Smoked Ham Hero Sandwich".to_string(),
                "Meatball Hero Sandwich".to_string(),
                "Gourmet Chicken Hero Sandwich".to_string(),
                "Philly Steak & Cheese Hero Sandwich".to_string(),
            ]
        );
    }

    #[test]
    fn story_contract_ready_requires_authority_identifier_coverage_for_document_briefing() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![
                "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
                "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            ],
            candidate_source_hints: vec![],
            attempted_urls: vec![
                "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                    .to_string(),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                    title: Some(
                        "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption"
                            .to_string(),
                    ),
                    excerpt: "The other two finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
                    title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
                    excerpt: "NIST has released FIPS 203, FIPS 204, and FIPS 205 as finalized post-quantum cryptography standards."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204, and FIPS 205 after NIST released the finalized standards."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                    title: Some(
                        "Federal Information Processing Standard (FIPS) 204".to_string(),
                    ),
                    excerpt: "Federal Information Processing Standard (FIPS) 204 specifies ML-DSA."
                        .to_string(),
                },
            ],
            min_sources: 3,
        };

        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);
        assert!(facts.briefing_standard_identifier_floor_met);
        assert!(!facts.briefing_authority_standard_identifier_floor_met);
        assert!(!story_completion_contract_ready(&pending, 1));
    }

    #[test]
    fn story_contract_ready_requires_primary_authority_source_when_authority_read_was_attempted() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![PendingSearchReadSummary {
                url: "https://www.nist.gov/pqc".to_string(),
                title: Some("Post-quantum cryptography | NIST".to_string()),
                excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
            }],
            attempted_urls: vec![
                "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                    .to_string(),
                "https://www.nist.gov/pqc".to_string(),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://cyberscoop.com/why-federal-it-leaders-must-act-now-to-deliver-nists-post-quantum-cryptography-transition-op-ed/".to_string(),
                    title: Some(
                        "Why federal IT leaders must act now to deliver NIST’s post-quantum cryptography transition"
                            .to_string(),
                    ),
                    excerpt: "CyberScoop covers federal post-quantum cryptography transition planning.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.cybersecuritydive.com/news/nist-post-quantum-cryptography-guidance-mapping/760638/".to_string(),
                    title: Some(
                        "NIST explains how post-quantum cryptography push overlaps with existing security guidance"
                            .to_string(),
                    ),
                    excerpt: "Cybersecurity Dive covers NIST post-quantum cryptography guidance mapping.".to_string(),
                },
            ],
            min_sources: 2,
        };

        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);
        assert_eq!(facts.available_primary_authority_source_count, 0);
        assert_eq!(facts.attempted_primary_authority_source_count, 1);
        assert_eq!(facts.selected_primary_authority_source_count, 0);
        assert!(!facts.briefing_primary_authority_source_floor_met);
        assert!(!story_completion_contract_ready(&pending, 1));
    }

    #[test]
    fn rendered_document_briefing_reserves_slot_for_independent_corroboration() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards&format=rss"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![
                "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption"
                    .to_string(),
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    .to_string(),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                    title: Some(
                        "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST"
                            .to_string(),
                    ),
                    excerpt: "NIST selected HQC in 2025 after finalizing FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                            .to_string(),
                    ),
                    excerpt: "NIST finalized FIPS 203, FIPS 204, and FIPS 205."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
                    title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
                    excerpt: "Independent analysis summarized the finalized standards set."
                        .to_string(),
                },
            ],
            min_sources: 2,
        };

        let summary = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-03-10T23:36:24Z UTC)\n\nWhat happened: As of 2026-03-10, retrieved authoritative sources identify the current standards as FIPS 203, FIPS 204, and FIPS 205.\n\nKey evidence:\n- According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST, NIST finalized FIPS 203, FIPS 204, and FIPS 205.\n- Independent analysis corroborated the finalized standards set.\n\nCitations:\n- NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST | https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards | 2026-03-10T23:36:24Z | retrieved_utc\n- Diving Into NIST’s New Post-Quantum Standards | https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/ | 2026-03-10T23:36:24Z | retrieved_utc\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T23:36:24Z\nOverall confidence: medium";

        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            summary,
        );

        assert_eq!(facts.available_primary_authority_source_count, 2);
        assert_eq!(facts.briefing_required_primary_authority_source_count, 1);
        assert_eq!(facts.selected_primary_authority_source_count, 1);
        assert!(facts.briefing_primary_authority_source_floor_met);
    }

    #[test]
    fn document_briefing_min_sources_completion_allows_stale_queued_reads_without_viable_followup()
    {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![
                "https://www.nist.gov/pqc".to_string(),
                "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards.".to_string(),
                },
            ],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards.".to_string(),
                },
            ],
            min_sources: 2,
        };

        assert!(web_pipeline_completion_terminalization_allowed(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            1,
        ));
        assert!(web_pipeline_completion_terminalization_allowed(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            0,
        ));
    }

    #[test]
    fn document_briefing_min_sources_completion_waits_for_viable_queued_followup_read() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![
                "https://www.nist.gov/pqc".to_string(),
                "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                    title: Some("FIPS 203, Module-Lattice-Based Key-Encapsulation Mechanism Standard | CSRC".to_string()),
                    excerpt: "NIST finalized FIPS 203 as one of the first post-quantum cryptography standards.".to_string(),
                },
            ],
            attempted_urls: vec!["https://www.nist.gov/pqc".to_string()],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://www.nist.gov/pqc".to_string(),
                title: Some("Post-quantum cryptography | NIST".to_string()),
                excerpt: "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world.".to_string(),
            }],
            min_sources: 1,
        };

        assert!(!web_pipeline_completion_terminalization_allowed(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            1,
        ));
    }

    #[test]
    fn rendered_summary_shape_facts_fail_for_story_collection_output_on_document_briefing_queries()
    {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt:
                        "NIST says now is the time to migrate to post-quantum encryption standards."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204, and FIPS 205.".to_string(),
                },
            ],
            min_sources: 2,
        };
        let bad_summary = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nComparison:\nExample.";
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            bad_summary,
        );

        assert!(!facts.briefing_document_layout_met);
        assert!(facts.briefing_query_layout_expected);
        assert_eq!(facts.briefing_rendered_layout_profile, "story_collection");
        assert!(!facts.briefing_render_heading_floor_met);
        assert!(facts.briefing_rendered_required_section_label_floor_met);
        assert_eq!(facts.briefing_story_header_count, 1);
        assert!(!facts.briefing_story_headers_absent);
        assert_eq!(facts.briefing_comparison_label_count, 1);
        assert!(!facts.briefing_comparison_absent);
        assert!(!facts.briefing_required_section_floor_met);
        assert!(!facts.briefing_query_grounding_floor_met);
        assert!(!facts.briefing_standard_identifier_floor_met);
        assert!(!facts.briefing_narrative_aggregation_floor_met);
        assert!(!facts.briefing_temporal_anchor_floor_met);
        assert!(!facts.briefing_postamble_floor_met);
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn rendered_summary_requires_read_backed_citations_for_document_briefing() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![
                "https://www.cyberark.com/resources/blog/nist-s-new-timeline-for-post-quantum-encryption"
                    .to_string(),
            ],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                title: Some(
                    "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                        .to_string(),
                ),
                excerpt: "NIST released FIPS 203, FIPS 204 and FIPS 205 as its first three finalized post-quantum encryption standards."
                    .to_string(),
            }],
            min_sources: 2,
        };
        let rendered_summary = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-03-10T20:58:06Z UTC)\n\nWhat happened: As of 2026-03-10, retrieved sources identify the current standards set as FIPS 203, FIPS 204, and FIPS 205.\n\nKey evidence: Supporting evidence is drawn from cited sources.\n\nCitations:\n- NIST Releases First 3 Finalized Post-Quantum Encryption Standards | https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards | 2026-03-10T20:58:06Z | retrieved_utc\n- NIST's new timeline for post-quantum encryption | https://www.cyberark.com/resources/blog/nist-s-new-timeline-for-post-quantum-encryption | 2026-03-10T20:58:06Z | retrieved_utc\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T20:58:06Z\nOverall confidence: high";
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert_eq!(facts.briefing_successful_citation_url_count, 1);
        assert_eq!(facts.briefing_unread_citation_url_count, 1);
        assert!(!facts.briefing_citation_read_backing_floor_met);
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn rendered_summary_requires_quality_of_cited_sources_for_document_briefing() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_217_927_000,
            deadline_ms: 1_773_217_987_000,
            candidate_urls: vec![
                "https://www.nist.gov/cybersecurity-and-privacy".to_string(),
                "https://webbook.nist.gov/chemistry/".to_string(),
                "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards"
                    .to_string(),
            ],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/cybersecurity-and-privacy".to_string(),
                    title: Some("Cybersecurity and privacy | NIST".to_string()),
                    excerpt: "NIST develops cybersecurity and privacy standards, guidelines, best practices, and resources."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://webbook.nist.gov/chemistry/".to_string(),
                    title: Some("NIST Chemistry WebBook".to_string()),
                    excerpt: "The NIST site provides chemical and physical property data for over 40,000 compounds."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                            .to_string(),
                    ),
                    excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as its first three finalized post-quantum encryption standards."
                        .to_string(),
                },
            ],
            min_sources: 2,
        };
        let rendered_summary = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-03-11T22:52:07Z UTC)\n\nWhat happened: As of 2026-03-11, retrieved authoritative sources identify the currently published standards as FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), and FIPS 205 (SLH-DSA). According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards, FIPS 205 is designed for digital signatures. According to Cybersecurity and privacy, NIST develops cybersecurity and privacy standards, guidelines, best practices, and resources. According to NIST Chemistry WebBook, NIST provides chemical and physical property data for over 40,000 compounds.\n\nKey evidence:\n- According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards, NIST finalized FIPS 203, FIPS 204, and FIPS 205.\n- According to Cybersecurity and privacy, NIST develops cybersecurity and privacy standards, guidelines, best practices, and resources.\n- According to NIST Chemistry WebBook, NIST provides chemical and physical property data for over 40,000 compounds.\n\nCitations:\n- NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST | https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards | 2026-03-11T22:52:07Z | retrieved_utc\n- Cybersecurity and privacy | NIST | https://www.nist.gov/cybersecurity-and-privacy | 2026-03-11T22:52:07Z | retrieved_utc\n- NIST Chemistry WebBook | https://webbook.nist.gov/chemistry/ | 2026-03-11T22:52:07Z | retrieved_utc\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T22:52:07Z\nOverall confidence: medium";
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::ExhaustedCandidates,
            rendered_summary,
        );

        assert_eq!(facts.briefing_selected_source_total, 3);
        assert_eq!(facts.briefing_selected_source_compatible, 2);
        assert!(!facts.briefing_selected_source_quality_floor_met);
        assert!(!facts.briefing_selected_source_identifier_coverage_floor_met);
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn rendered_summary_rejects_authority_only_optional_inventory_below_floor() {
        let pending = retained_like_nist_briefing_pending();
        let rendered_summary = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.' (as of 2026-04-02T04:03:13Z UTC)\n\nWhat happened: As of 2026-04-02, retrieved authoritative sources identify the currently published standards as FIPS 203. According to IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC, IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process. According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards | CSRC, NIST finalized FIPS 203, FIPS 204, and FIPS 205 as its first post-quantum cryptography standards.\n\nKey evidence:\n- According to IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC, IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process.\n- According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards | CSRC, NIST finalized FIPS 203, FIPS 204, and FIPS 205 as its first post-quantum cryptography standards.\n\nCitations:\n- IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC | https://csrc.nist.gov/pubs/ir/8413/upd1/final | 2026-04-02T04:03:13Z | retrieved_utc\n- IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC | https://csrc.nist.gov/pubs/ir/8413/final | 2026-04-02T04:03:13Z | retrieved_utc\n- NIST Releases First 3 Finalized Post-Quantum Encryption Standards | CSRC | https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved | 2026-04-02T04:03:13Z | retrieved_utc\nRun date (UTC): 2026-04-02\nRun timestamp (UTC): 2026-04-02T04:03:13Z\nOverall confidence: high";
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert!(!facts.briefing_summary_inventory_floor_met);
        assert_eq!(facts.briefing_standard_identifier_group_floor, 1);
        assert_eq!(facts.briefing_summary_inventory_identifier_count, 1);
        assert_eq!(
            facts.briefing_summary_inventory_required_identifier_count,
            0
        );
        assert_eq!(
            facts.briefing_summary_inventory_optional_identifier_count,
            1
        );
        assert_eq!(
            facts.briefing_summary_inventory_authority_identifier_count,
            1
        );
        assert!(facts.briefing_authority_standard_identifier_floor_met);
        assert!(facts.briefing_evidence_block_floor_met);
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn rendered_summary_accepts_authority_backed_optional_inventory_when_required_identifier_floor_is_met_elsewhere(
    ) {
        let pending = retained_like_nist_briefing_pending();
        let rendered_summary = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.' (as of 2026-04-02T04:03:13Z UTC)\n\nWhat happened: As of 2026-04-02, retrieved authoritative sources identify the currently published standards as FIPS 203, FIPS 204, and FIPS 205. According to IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC, IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process. According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards | CSRC, NIST finalized FIPS 203, FIPS 204, and FIPS 205 as its first post-quantum cryptography standards.\n\nKey evidence:\n- According to IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC, IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process.\n- According to NIST Releases First 3 Finalized Post-Quantum Encryption Standards | CSRC, NIST finalized FIPS 203, FIPS 204, and FIPS 205 as its first post-quantum cryptography standards.\n\nCitations:\n- IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC | https://csrc.nist.gov/pubs/ir/8413/upd1/final | 2026-04-02T04:03:13Z | retrieved_utc\n- IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC | https://csrc.nist.gov/pubs/ir/8413/final | 2026-04-02T04:03:13Z | retrieved_utc\n- NIST Releases First 3 Finalized Post-Quantum Encryption Standards | CSRC | https://csrc.nist.gov/News/2024/postquantum-cryptography-fips-approved | 2026-04-02T04:03:13Z | retrieved_utc\nRun date (UTC): 2026-04-02\nRun timestamp (UTC): 2026-04-02T04:03:13Z\nOverall confidence: high";
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert_eq!(facts.briefing_standard_identifier_group_floor, 1);
        assert_eq!(facts.briefing_standard_identifier_count, 4);
        assert_eq!(facts.briefing_required_standard_identifier_count, 1);
        assert_eq!(
            facts.briefing_summary_inventory_required_identifier_count,
            0
        );
        assert_eq!(
            facts.briefing_summary_inventory_optional_identifier_count,
            3
        );
        assert_eq!(
            facts.briefing_summary_inventory_authority_identifier_count,
            3
        );
        assert!(facts.briefing_authority_standard_identifier_floor_met);
        assert!(facts.briefing_summary_inventory_floor_met);
    }

    #[test]
    fn rendered_summary_shape_facts_observe_story_collection_output_even_when_contract_drifts() {
        let mut drifted_contract = nist_briefing_contract();
        drifted_contract.source_independence_min = 1;
        drifted_contract.structured_record_preferred = true;
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(drifted_contract),
            url: "https://www.bing.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt:
                        "NIST says now is the time to migrate to post-quantum encryption standards."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt: "IBM summarized FIPS 203, FIPS 204, and FIPS 205.".to_string(),
                },
            ],
            min_sources: 1,
        };
        let bad_summary = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.";
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            bad_summary,
        );

        assert!(facts.briefing_query_layout_expected);
        assert_eq!(facts.briefing_layout_profile, "single_snapshot");
        assert_eq!(facts.briefing_rendered_layout_profile, "story_collection");
        assert!(!facts.briefing_document_layout_met);
        assert_eq!(facts.briefing_story_header_count, 1);
        assert!(!facts.briefing_story_headers_absent);
    }

    #[test]
    fn rendered_summary_citation_urls_collect_all_story_collection_blocks() {
        let required_sections = vec![
            HybridSectionSpec {
                key: "what_happened".to_string(),
                label: "What happened".to_string(),
                required: true,
            },
            HybridSectionSpec {
                key: "key_evidence".to_string(),
                label: "Key evidence".to_string(),
                required: true,
            },
        ];
        let rendered_summary = "Web retrieval summary for 'Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.'\n\nStory 1: Brothers Italian Cuisine\nWhat happened: Example.\nKey evidence: Example.\nCitations:\n- Menu | https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/ | 2026-03-11T19:58:57Z | retrieved_utc\nConfidence: high\n\nStory 2: Coach House Restaurant\nWhat happened: Example.\nKey evidence: Example.\nCitations:\n- Menu | https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/ | 2026-03-11T19:58:57Z | retrieved_utc\nConfidence: high\n\nStory 3: Red Tomato and Wine Restaurant\nWhat happened: Example.\nKey evidence: Example.\nCitations:\n- Menu | https://www.restaurantji.com/sc/anderson/red-tomato-and-wine-restaurant-/menu/ | 2026-03-11T19:58:57Z | retrieved_utc\nComparison:\n- Example.\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T19:58:57Z\nOverall confidence: high";

        assert_eq!(
            rendered_summary_citation_urls(rendered_summary, &required_sections),
            vec![
                "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/"
                    .to_string(),
                "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
                    .to_string(),
                "https://www.restaurantji.com/sc/anderson/red-tomato-and-wine-restaurant-/menu/"
                    .to_string(),
            ]
        );
    }

    #[test]
    fn rendered_live_weather_snapshot_reply_satisfies_single_snapshot_contract() {
        let pending = weather_snapshot_pending();
        let rendered_summary = "The current weather in Anderson, SC, is as follows:\n\n- Condition: Fair\n- Temperature: 65°F (18°C)\n- Humidity: 93%\n- Wind Speed: SW 3 mph\n- Barometer: 30.06 in (1017.2 mb)\n- Visibility: 10.00 miles\n\nThis information is based on the latest update from the Anderson County Airport (KAND) as of 8:56 am EDT on March 11th. For more details, visit https://forecast.weather.gov/MapClick.php?lat=34.5186&lon=-82.6458&unit=0&lg=english&FcstType=graphical\n\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T13:19:18Z\nOverall confidence: high";

        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert_eq!(facts.briefing_layout_profile, "single_snapshot");
        assert_eq!(facts.briefing_rendered_layout_profile, "single_snapshot");
        assert!(facts.single_snapshot_rendered_layout_met);
        assert_eq!(facts.single_snapshot_required_citation_count, 1);
        assert!(facts.single_snapshot_rendered_metric_line_floor_met);
        assert_eq!(facts.single_snapshot_rendered_support_url_count, 1);
        assert!(facts.single_snapshot_rendered_support_url_floor_met);
        assert_eq!(facts.single_snapshot_rendered_read_backed_url_count, 1);
        assert!(facts.single_snapshot_rendered_read_backed_url_floor_met);
        assert!(facts.single_snapshot_rendered_temporal_signal_present);
        assert!(facts.single_snapshot_metric_grounding);
        assert!(final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn rendered_current_office_holder_snapshot_reply_satisfies_single_snapshot_contract() {
        let pending = PendingSearchCompletion {
            query: "Who is the current Secretary-General of the UN?".to_string(),
            query_contract: "Who is the current Secretary-General of the UN?".to_string(),
            retrieval_contract: Some(WebRetrievalContract {
                contract_version: "test.v1".to_string(),
                entity_cardinality_min: 1,
                comparison_required: false,
                currentness_required: true,
                runtime_locality_required: false,
                source_independence_min: 1,
                citation_count_min: 1,
                structured_record_preferred: true,
                ordered_collection_preferred: false,
                link_collection_preferred: false,
                canonical_link_out_preferred: false,
                geo_scoped_detail_required: false,
                discovery_surface_required: false,
                entity_diversity_required: false,
                scalar_measure_required: false,
                browser_fallback_allowed: true,
            }),
            url: "https://search.brave.com/search?q=current+Secretary-General+of+the+United+Nations"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_776_200_894_000,
            deadline_ms: 1_776_200_954_000,
            candidate_urls: vec!["https://ask.un.org/faq/14625".to_string()],
            candidate_source_hints: vec![],
            attempted_urls: vec!["https://ask.un.org/faq/14625".to_string()],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://ask.un.org/faq/14625".to_string(),
                title: Some(
                    "UN Ask DAG ask.un.org faq 14625 Who is and has been Secretary-General of the United Nations? - Ask DAG!"
                        .to_string(),
                ),
                excerpt:
                    "Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations."
                        .to_string(),
            }],
            min_sources: 1,
        };
        let rendered_summary = "Current snapshot (as of 2026-04-14T21:08:14Z UTC):\n\nCurrent answer: Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations.\n\nCitations:\n- UN Ask DAG ask.un.org faq 14625 Who is and has been Secretary-General of the United Nations? - Ask DAG! | https://ask.un.org/faq/14625 | 2026-04-14T21:08:14Z | retrieved_utc | excerpt: Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations.\n\nRun date (UTC): 2026-04-14\nRun timestamp (UTC): 2026-04-14T21:08:14Z\nOverall confidence: high";

        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert_eq!(facts.briefing_layout_profile, "single_snapshot");
        assert_eq!(facts.briefing_rendered_layout_profile, "single_snapshot");
        assert!(facts.single_snapshot_rendered_layout_met);
        assert_eq!(facts.single_snapshot_required_citation_count, 1);
        assert!(facts.single_snapshot_rendered_metric_line_floor_met);
        assert_eq!(facts.single_snapshot_rendered_support_url_count, 1);
        assert!(facts.single_snapshot_rendered_support_url_floor_met);
        assert_eq!(facts.single_snapshot_rendered_read_backed_url_count, 1);
        assert!(facts.single_snapshot_rendered_read_backed_url_floor_met);
        assert!(facts.single_snapshot_rendered_temporal_signal_present);
        assert!(facts.single_snapshot_metric_grounding);
        assert!(final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn current_office_holder_snapshot_uses_identity_contract_not_metric_contract() {
        let query = "Who is the current Secretary-General of the UN?";
        let pending = PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract: Some(
                crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                    .expect("retrieval contract"),
            ),
            url: "https://search.brave.com/search?q=who+secretary+general".to_string(),
            started_step: 1,
            started_at_ms: 1_776_236_380_000,
            deadline_ms: 1_776_236_500_000,
            candidate_urls: vec![
                "https://ask.un.org/faq/14625".to_string(),
                "https://en.wikipedia.org/wiki/Ant%C3%B3nio_Guterres".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://ask.un.org/faq/14625".to_string(),
                    title: Some(
                        "UN Ask DAG ask.un.org faq 14625 Who is and has been Secretary-General of the United Nations? - Ask DAG!"
                            .to_string(),
                    ),
                    excerpt:
                        "Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://en.wikipedia.org/wiki/Ant%C3%B3nio_Guterres".to_string(),
                    title: Some(
                        "Wikipedia en.wikipedia.org wiki Ant\u{f3}nio_Guterres Ant\u{f3}nio Guterres - Wikipedia"
                            .to_string(),
                    ),
                    excerpt:
                        "17 hours ago - Guterres was elected secretary-general in October 2016, succeeding Ban Ki-moon at the beginning of the following year."
                            .to_string(),
                },
            ],
            attempted_urls: vec![
                "https://ask.un.org/faq/14625".to_string(),
                "https://en.wikipedia.org/wiki/Ant%C3%B3nio_Guterres".to_string(),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://ask.un.org/faq/14625".to_string(),
                    title: Some(
                        "Who is and has been Secretary-General of the United Nations? - Ask DAG!"
                            .to_string(),
                    ),
                    excerpt:
                        "Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://en.wikipedia.org/wiki/Ant%C3%B3nio_Guterres".to_string(),
                    title: Some("Ant\u{f3}nio Guterres - Wikipedia".to_string()),
                    excerpt:
                        "17 hours ago - Guterres was elected secretary-general in October 2016, succeeding Ban Ki-moon at the beginning of the following year."
                            .to_string(),
                },
            ],
            min_sources: 1,
        };

        assert!(!single_snapshot_requires_current_metric_observation_contract(&pending));
        assert!(single_snapshot_requires_subject_identity_contract(&pending));
        assert!(single_snapshot_has_subject_identity_grounding(&pending));

        let rendered =
            synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            &rendered,
        );

        assert!(rendered.contains("Current answer: Ant\u{f3}nio Guterres is the current Secretary-General of the United Nations."));
        assert!(
            rendered.contains("https://ask.un.org/faq/14625"),
            "{rendered}"
        );
        assert!(facts.single_snapshot_metric_grounding, "{facts:#?}");
        assert!(
            final_web_completion_contract_ready(&facts),
            "{facts:#?}\n{rendered}"
        );
        assert_eq!(
            web_pipeline_completion_reason(&pending, 1_776_236_440_000),
            Some(WebPipelineCompletionReason::MinSourcesReached)
        );
    }

    #[test]
    fn latest_openai_api_pricing_snapshot_stops_after_primary_authority_read() {
        let pending = openai_api_pricing_snapshot_pending();
        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);

        assert_eq!(facts.briefing_layout_profile, "single_snapshot");
        assert_eq!(facts.available_primary_authority_source_count, 1);
        assert_eq!(facts.selected_primary_authority_source_count, 1);
        assert!(facts.briefing_primary_authority_source_floor_met);
        assert!(facts.single_snapshot_metric_grounding);
        assert!(story_completion_contract_ready(&pending, 1));
        assert!(!single_snapshot_has_viable_followup_candidate(
            &pending,
            &pending.query_contract
        ));
        assert_eq!(
            web_pipeline_completion_reason(&pending, 1_776_227_500_000),
            Some(WebPipelineCompletionReason::MinSourcesReached)
        );
    }

    #[test]
    fn liveish_openai_pricing_anchor_read_is_preserved_in_merged_authority_inventory() {
        let pending = liveish_openai_api_pricing_anchor_pending();
        let merged = merged_story_sources(&pending);
        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);

        assert!(
            merged
                .iter()
                .any(|source| source.url == "https://openai.com/api/pricing/"),
            "official successful read should survive merged-story filtering for host-anchored pricing queries"
        );
        assert_eq!(facts.available_primary_authority_source_count, 1);
        assert_eq!(facts.selected_primary_authority_source_count, 1);
        assert!(facts.briefing_primary_authority_source_floor_met);
    }

    #[test]
    fn liveish_openai_pricing_anchor_plus_metric_support_completes_single_snapshot() {
        let mut pending = liveish_openai_api_pricing_anchor_pending();
        pending.successful_reads[0].excerpt =
            "Image: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs"
                .to_string();
        pending.attempted_urls.push(
            "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services"
                .to_string(),
        );
        pending.successful_reads.push(PendingSearchReadSummary {
            url: "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services"
                .to_string(),
            title: Some("OpenAI API Pricing & Services - A Comprehensive Guide".to_string()),
            excerpt: "Price: Input: $1.10 per 1M tokens, Cached input: $0.275 per 1M tokens, Output: $4.40 per 1M tokens.".to_string(),
        });

        let facts =
            final_web_completion_facts(&pending, WebPipelineCompletionReason::MinSourcesReached);

        assert_eq!(facts.available_primary_authority_source_count, 1);
        assert_eq!(facts.selected_primary_authority_source_count, 1);
        assert!(facts.single_snapshot_metric_grounding);
        assert!(facts.briefing_primary_authority_source_floor_met);
        assert!(story_completion_contract_ready(&pending, 1), "{facts:#?}");
    }

    #[test]
    fn rendered_latest_openai_api_pricing_snapshot_accepts_official_authority_citation() {
        let pending = openai_api_pricing_snapshot_pending();
        let rendered_summary = "Current snapshot (as of 2026-04-15T04:30:41Z UTC):\n\nCurrent conditions: image input is $8.00, cached image input is $2.00, and image output is $32.00.\n\nCitations:\n- API Pricing | OpenAI API | https://openai.com/api/pricing/ | 2026-04-15T04:30:41Z | retrieved_utc | excerpt: Image: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs\n\nRun date (UTC): 2026-04-15\nRun timestamp (UTC): 2026-04-15T04:30:41Z\nOverall confidence: high";

        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert_eq!(facts.briefing_layout_profile, "single_snapshot");
        assert_eq!(facts.selected_primary_authority_source_count, 1);
        assert!(facts.briefing_primary_authority_source_floor_met);
        assert!(facts.single_snapshot_rendered_layout_met);
        assert!(facts.single_snapshot_rendered_read_backed_url_floor_met);
        assert!(final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn synthesized_latest_openai_api_pricing_snapshot_handles_full_official_page_surface() {
        let requested_url = "https://openai.com/api/pricing/";
        let query = "What is the latest OpenAI API pricing?";
        let pending = PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract: Some(
                crate::agentic::web::derive_web_retrieval_contract(query, None)
                    .expect("retrieval contract"),
            ),
            url: "https://search.brave.com/search?q=openai+api+pricing".to_string(),
            started_step: 1,
            started_at_ms: 1_776_229_080_000,
            deadline_ms: 1_776_229_200_000,
            candidate_urls: vec![requested_url.to_string()],
            candidate_source_hints: vec![PendingSearchReadSummary {
                url: requested_url.to_string(),
                title: Some("OpenAI API Pricing | OpenAI".to_string()),
                excerpt:
                    "Explore OpenAI API pricing for GPT-5.4, multimodal models, and tools."
                        .to_string(),
            }],
            attempted_urls: vec![requested_url.to_string()],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: requested_url.to_string(),
                title: Some("OpenAI API Pricing | OpenAI".to_string()),
                excerpt: concat!(
                    "Our frontier models are designed to spend more time thinking before producing a response, ",
                    "making them ideal for complex, multi-step problems.\n\n",
                    "Our cheapest GPT-5.4-class model for simple high-volume tasks.\n\n",
                    "Pricing above reflects standard processing rates for context lengths under 270K.\n\n",
                    "Now: 1 GB for $0.03 / 64GB for $1.92 per container. ",
                    "Starting March 31, 2026: 1 GB for $0.03 / 64GB for $1.92 per 20-minute session pass.\n\n",
                    "State-of-the-art image generation model.\n\n",
                    "Image: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs ",
                    "Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs"
                )
                .to_string(),
            }],
            min_sources: 1,
        };

        let summary =
            synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            &summary,
        );

        assert!(
            summary.contains("Current conditions")
                || summary.contains("Current pricing")
                || summary.contains("Available observed details"),
            "expected a single-snapshot metric summary, got: {summary}"
        );
        assert!(
            summary.contains("$8.00") || summary.contains("$32.00"),
            "expected pricing metrics in rendered summary, got: {summary}"
        );
        assert!(
            !summary.contains("1 GB for $0.03") && !summary.contains("per container"),
            "expected rendered summary to avoid unrelated storage/session pricing, got: {summary}"
        );
        assert!(
            !summary.contains("Estimated-right-now:")
                && !summary.contains("Current metric status:")
                && !summary.contains("Data caveat:")
                && !summary.contains("Next step: Open"),
            "expected strong official pricing snapshots to render without limitation boilerplate, got: {summary}"
        );
        assert_eq!(facts.briefing_layout_profile, "single_snapshot");
        assert_eq!(facts.briefing_rendered_layout_profile, "single_snapshot");
        assert!(facts.single_snapshot_rendered_layout_met, "{facts:#?}");
        assert!(
            facts.single_snapshot_rendered_metric_line_floor_met,
            "{facts:#?}"
        );
        assert!(
            facts.single_snapshot_rendered_read_backed_url_floor_met,
            "{facts:#?}"
        );
        assert!(
            final_web_completion_contract_ready(&facts),
            "{summary}\n\n{facts:#?}"
        );
    }

    #[test]
    fn rendered_latest_openai_api_pricing_snapshot_rejects_non_authority_only_citation_when_official_read_is_available(
    ) {
        let mut pending = openai_api_pricing_snapshot_pending();
        pending.successful_reads.push(PendingSearchReadSummary {
            url: "https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services"
                .to_string(),
            title: Some("Making Sense of the OpenAI API's Pricing and Services".to_string()),
            excerpt:
                "A guide to understanding the OpenAI API's pricing, including token costs and service tiers."
                    .to_string(),
        });
        let rendered_summary = "Current snapshot (as of 2026-04-15T04:30:41Z UTC):\n\nCurrent conditions: image input is $8.00, cached image input is $2.00, and image output is $32.00.\n\nCitations:\n- Making Sense of the OpenAI API's Pricing and Services | https://www.arsturn.com/blog/making-sense-of-the-openai-apis-pricing-and-services | 2026-04-15T04:30:41Z | retrieved_utc | excerpt: A guide to understanding the OpenAI API's pricing, including token costs and service tiers.\n\nRun date (UTC): 2026-04-15\nRun timestamp (UTC): 2026-04-15T04:30:41Z\nOverall confidence: high";

        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert!(facts.single_snapshot_rendered_layout_met);
        assert!(facts.single_snapshot_rendered_read_backed_url_floor_met);
        assert_eq!(facts.selected_primary_authority_source_count, 0);
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn rendered_single_snapshot_reply_requires_all_required_citations_to_be_read_backed() {
        let pending = PendingSearchCompletion {
            query: "What's the current price of Bitcoin?".to_string(),
            query_contract: "What's the current price of Bitcoin?".to_string(),
            retrieval_contract: Some(WebRetrievalContract {
                contract_version: "test.v1".to_string(),
                entity_cardinality_min: 1,
                comparison_required: false,
                currentness_required: true,
                runtime_locality_required: false,
                source_independence_min: 1,
                citation_count_min: 2,
                structured_record_preferred: true,
                ordered_collection_preferred: false,
                link_collection_preferred: false,
                canonical_link_out_preferred: false,
                geo_scoped_detail_required: false,
                discovery_surface_required: false,
                entity_diversity_required: false,
                scalar_measure_required: true,
                browser_fallback_allowed: true,
            }),
            url: "https://search.brave.com/search?q=current+bitcoin+price".to_string(),
            started_step: 1,
            started_at_ms: 1_773_236_577_000,
            deadline_ms: 1_773_236_637_000,
            candidate_urls: vec!["https://crypto.com/us/price/bitcoin".to_string()],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://www.worldcoinindex.com/coin/bitcoin".to_string(),
                title: Some("Bitcoin price | index, chart and news | WorldCoinIndex".to_string()),
                excerpt: "Bitcoin price right now: $86,743.63 USD.".to_string(),
            }],
            min_sources: 2,
        };
        let rendered_summary = "Right now (as of 2026-03-11T13:42:57Z UTC):\n\nCurrent conditions from cited source text: Bitcoin price right now: $86,743.63 USD.\n\nCitations:\n- Bitcoin price | index, chart and news | WorldCoinIndex | https://www.worldcoinindex.com/coin/bitcoin | 2026-03-11T13:42:57Z | retrieved_utc\n- Bitcoin price - Crypto.com | https://crypto.com/us/price/bitcoin | 2026-03-11T13:42:57Z | retrieved_utc\n\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T13:42:57Z\nOverall confidence: high";

        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert_eq!(facts.single_snapshot_required_citation_count, 2);
        assert_eq!(facts.single_snapshot_rendered_support_url_count, 2);
        assert_eq!(facts.single_snapshot_rendered_read_backed_url_count, 1);
        assert!(facts.single_snapshot_rendered_support_url_floor_met);
        assert!(!facts.single_snapshot_rendered_read_backed_url_floor_met);
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn story_collection_output_fails_single_snapshot_contract() {
        let pending = weather_snapshot_pending();
        let rendered_summary = "Web retrieval summary for 'What's the weather like right now in Anderson, SC?'\n\nStory 1: Anderson weather\nWhat happened: Current conditions are fair and 65°F.\nKey evidence: https://forecast.weather.gov/MapClick.php?lat=34.5186&lon=-82.6458&unit=0&lg=english&FcstType=graphical\n\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T13:19:18Z\nOverall confidence: high";

        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert_eq!(facts.briefing_layout_profile, "single_snapshot");
        assert_eq!(facts.briefing_rendered_layout_profile, "story_collection");
        assert!(!facts.single_snapshot_rendered_layout_met);
        assert!(!final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn rendered_story_collection_menu_comparison_binds_all_cited_menu_sources() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let pending = PendingSearchCompletion {
            query: query.to_string(),
            query_contract: query.to_string(),
            retrieval_contract: Some(
                crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                    .expect("retrieval contract"),
            ),
            url: "https://www.restaurantji.com/sc/anderson/italian/".to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Brothers Italian Cuisine",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Coach House Restaurant",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
                format!(
                    "ioi://local-business-expansion/query/{}",
                    local_business_expansion_query(
                        "Red Tomato and Wine Restaurant",
                        query,
                        Some("Anderson, SC"),
                    )
                    .expect("expansion query")
                ),
            ],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/"
                        .to_string(),
                    title: Some("Menu for Brothers Italian Cuisine, Anderson, SC - Restaurantji".to_string()),
                    excerpt:
                        "Item inventory includes Brothers Sepcial Shrimp Pasta, 2 Plates of 1 2 a Chef Salad, 1 2 an Italian Stromboli, Grilled Chicken Salad, and Meat Lovers Calzone."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/"
                        .to_string(),
                    title: Some("Menu for Coach House Restaurant, Anderson, SC - Restaurantji".to_string()),
                    excerpt:
                        "Item inventory includes Served with Sauteed Onions and Brown Gravy, Tuesday Dinner Special Chopped Steak, Broccoli Stuffed Chicken Breast, Country Fried Steak Sandwich, and Assorted Home Made Cakes."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.restaurantji.com/sc/anderson/red-tomato-and-wine-restaurant-/menu/"
                        .to_string(),
                    title: Some("Menu for Red Tomato and Wine Restaurant, Anderson, SC - Restaurantji".to_string()),
                    excerpt:
                        "Item inventory includes Ziti with Meat and Rose Sauce, Hummus with Grilled Pita Bread, Fettuccine Alfredo with Shrimp, Spaghetti with Meat Sauce, and Three Cheese Manicotti."
                            .to_string(),
                },
            ],
            min_sources: 3,
        };
        let rendered_summary = "Web retrieval summary for 'Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.' (as of 2026-03-11T19:58:57Z UTC)\n\nStory 1: Brothers Italian Cuisine\nWhat happened: Brothers Italian Cuisine remains one of the better-reviewed Italian options in Anderson.\nKey evidence: Item inventory includes Brothers Sepcial Shrimp Pasta, 2 Plates of 1 2 a Chef Salad, 1 2 an Italian Stromboli, Grilled Chicken Salad, and Meat Lovers Calzone.\nCitations:\n- Menu for Brothers Italian Cuisine, Anderson, SC - Restaurantji | https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/ | 2026-03-11T19:58:57Z | retrieved_utc\nConfidence: high\n\nStory 2: Coach House Restaurant\nWhat happened: Coach House Restaurant also surfaces as a strong-reviewed Anderson restaurant with Italian dishes.\nKey evidence: Item inventory includes Served with Sauteed Onions and Brown Gravy, Tuesday Dinner Special Chopped Steak, Broccoli Stuffed Chicken Breast, Country Fried Steak Sandwich, and Assorted Home Made Cakes.\nCitations:\n- Menu for Coach House Restaurant, Anderson, SC - Restaurantji | https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/menu/ | 2026-03-11T19:58:57Z | retrieved_utc\nConfidence: high\n\nStory 3: Red Tomato and Wine Restaurant\nWhat happened: Red Tomato and Wine Restaurant completes the three-way comparison set.\nKey evidence: Item inventory includes Ziti with Meat and Rose Sauce, Hummus with Grilled Pita Bread, Fettuccine Alfredo with Shrimp, Spaghetti with Meat Sauce, and Three Cheese Manicotti.\nCitations:\n- Menu for Red Tomato and Wine Restaurant, Anderson, SC - Restaurantji | https://www.restaurantji.com/sc/anderson/red-tomato-and-wine-restaurant-/menu/ | 2026-03-11T19:58:57Z | retrieved_utc\nComparison:\n- Brothers Italian Cuisine emphasizes pasta, salads, and calzones.\n- Coach House Restaurant emphasizes house specials and comfort dishes.\n- Red Tomato and Wine Restaurant emphasizes pasta, Mediterranean starters, and Italian mains.\nRun date (UTC): 2026-03-11\nRun timestamp (UTC): 2026-03-11T19:58:57Z\nOverall confidence: high";

        let facts = final_web_completion_facts_with_rendered_summary(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            rendered_summary,
        );

        assert_eq!(facts.briefing_rendered_layout_profile, "story_collection");
        assert_eq!(facts.selected_source_urls.len(), 3);
        assert_eq!(facts.briefing_successful_citation_url_count, 3);
        assert_eq!(facts.local_business_menu_inventory_source_urls.len(), 3);
        assert!(facts.local_business_menu_inventory_total_item_count >= 6);
        assert!(facts.local_business_menu_inventory_floor_met);
        assert!(final_web_completion_contract_ready(&facts));
    }

    #[test]
    fn final_summary_selection_prefers_contract_compliant_document_briefing_output() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/pqc".to_string(),
                    title: Some("Post-quantum cryptography | NIST".to_string()),
                    excerpt:
                        "December 8, 2025 - These Federal Information Processing Standards are mandatory for federal systems and adopted around the world."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://research.ibm.com/blog/nist-pqc-standards".to_string(),
                    title: Some(
                        "NIST’s post-quantum cryptography standards are here - IBM Research"
                            .to_string(),
                    ),
                    excerpt:
                        "IBM summarized FIPS 203, FIPS 204 and FIPS 205 after NIST released the standards."
                            .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://newsroom.ibm.com/2024-08-13-ibm-developed-algorithms-announced-as-worlds-first-post-quantum-cryptography-standards".to_string(),
                    title: Some(
                        "IBM-Developed Algorithms Announced as NIST's First Published Post-Quantum Cryptography Standards"
                            .to_string(),
                    ),
                    excerpt:
                        "IBM-developed algorithms announced as NIST's first published post-quantum cryptography standards."
                            .to_string(),
                },
            ],
            min_sources: 3,
        };
        let deterministic_summary =
            synthesize_web_pipeline_reply(&pending, WebPipelineCompletionReason::MinSourcesReached);
        let bad_summary = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nComparison:\nExample.".to_string();
        let selection = select_final_web_summary_from_candidates(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            vec![
                FinalWebSummaryCandidate {
                    provider: "hybrid",
                    summary: bad_summary,
                },
                FinalWebSummaryCandidate {
                    provider: "deterministic",
                    summary: deterministic_summary.clone(),
                },
            ],
        )
        .expect("summary selection");

        assert_eq!(selection.provider, "deterministic");
        assert!(selection.contract_ready);
        assert_eq!(selection.summary, deterministic_summary);
        assert_eq!(selection.evaluations.len(), 2);
        assert!(!selection.evaluations[0].contract_ready);
        assert_eq!(selection.evaluations[0].provider, "hybrid");
        assert_eq!(
            selection.evaluations[0]
                .facts
                .briefing_rendered_layout_profile,
            "story_collection"
        );
        assert!(selection.evaluations[1].contract_ready);
        assert_eq!(selection.evaluations[1].provider, "deterministic");
    }

    #[test]
    fn final_summary_selection_prefers_stronger_non_ready_document_briefing_fallback() {
        let pending = PendingSearchCompletion {
            query: "nist post quantum cryptography standards".to_string(),
            query_contract:
                "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing."
                    .to_string(),
            retrieval_contract: Some(nist_briefing_contract()),
            url: "https://search.brave.com/search?q=nist+post+quantum+cryptography+standards"
                .to_string(),
            started_step: 1,
            started_at_ms: 1_773_117_248_754,
            deadline_ms: 1_773_117_308_754,
            candidate_urls: vec![],
            candidate_source_hints: vec![],
            attempted_urls: vec![],
            blocked_urls: vec![],
            successful_reads: vec![
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption".to_string(),
                    title: Some(
                        "NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST"
                            .to_string(),
                    ),
                    excerpt: "The other finished standards, FIPS 204 and FIPS 205, contain digital signature algorithms while HQC serves as a backup."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/".to_string(),
                    title: Some("Diving Into NIST’s New Post-Quantum Standards".to_string()),
                    excerpt: "NIST has released FIPS 203, FIPS 204, and FIPS 205 as its first finalized post-quantum cryptography standards."
                        .to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards".to_string(),
                    title: Some(
                        "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST"
                            .to_string(),
                    ),
                    excerpt: "NIST released FIPS 203, FIPS 204, and FIPS 205 as the first finalized post-quantum encryption standards."
                        .to_string(),
                },
            ],
            min_sources: 2,
        };
        let better_summary = "Briefing for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.' (as of 2026-03-10T12:19:24Z UTC)\n\nWhat happened: As of 2026-03-10, retrieved authoritative sources identify the currently published standards as FIPS 204 and FIPS 205. According to NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST, the other finished standards are FIPS 204 and FIPS 205 while HQC serves as a backup. According to Diving Into NIST’s New Post-Quantum Standards, the finalized standards set includes FIPS 203, FIPS 204, and FIPS 205.\n\nKey evidence:\n- According to NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST, the other finished standards are FIPS 204 and FIPS 205 while HQC serves as a backup.\n- According to Diving Into NIST’s New Post-Quantum Standards, the finalized standards set includes FIPS 203, FIPS 204, and FIPS 205.\n\nCitations:\n- NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST | https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption | 2026-03-10T12:19:24Z | retrieved_utc\n- Diving Into NIST’s New Post-Quantum Standards | https://terraquantum.swiss/news/diving-into-nists-new-post-quantum-standards/ | 2026-03-10T12:19:24Z | retrieved_utc\n\nRun date (UTC): 2026-03-10\nRun timestamp (UTC): 2026-03-10T12:19:24Z\nOverall confidence: medium"
            .to_string();
        let worse_summary = "Web retrieval summary for 'Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.'\n\nStory 1: Example\nWhat happened: Example.\nKey evidence: Example.\n\nCitations:\n- NIST Selects HQC as Fifth Algorithm for Post-Quantum Encryption | NIST | https://www.nist.gov/news-events/news/2025/03/nist-selects-hqc-fifth-algorithm-post-quantum-encryption | 2026-03-10T12:19:24Z | retrieved_utc"
            .to_string();

        let selection = select_final_web_summary_from_candidates(
            &pending,
            WebPipelineCompletionReason::MinSourcesReached,
            vec![
                FinalWebSummaryCandidate {
                    provider: "hybrid",
                    summary: better_summary.clone(),
                },
                FinalWebSummaryCandidate {
                    provider: "deterministic",
                    summary: worse_summary,
                },
            ],
        )
        .expect("summary selection");

        assert_eq!(selection.provider, "hybrid");
        assert!(!selection.contract_ready);
        assert_eq!(selection.summary, better_summary);
        assert!(selection.facts.briefing_document_layout_met);
        assert_eq!(
            selection.facts.briefing_rendered_layout_profile,
            "document_briefing"
        );
        assert_eq!(selection.evaluations.len(), 2);
        assert!(!selection.evaluations[0].contract_ready);
        assert!(!selection.evaluations[1].contract_ready);
        assert_eq!(
            selection.evaluations[1]
                .facts
                .briefing_rendered_layout_profile,
            "story_collection"
        );
    }
}
