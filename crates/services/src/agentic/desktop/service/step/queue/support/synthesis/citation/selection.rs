use super::*;

pub(crate) fn citation_ids_for_story(
    source: &PendingSearchReadSummary,
    candidates: &[CitationCandidate],
    used_urls: &mut BTreeSet<String>,
    citations_per_story: usize,
    prefer_host_diversity: bool,
    envelope_constraints: &ConstraintSet,
    envelope_policy: ResolutionPolicy,
) -> Vec<String> {
    if candidates.is_empty() {
        return Vec::new();
    }

    let insights_by_id =
        weighted_insights_for_story(source, candidates, envelope_constraints, envelope_policy)
            .into_iter()
            .map(|insight| (insight.id.clone(), insight))
            .collect::<BTreeMap<_, _>>();
    let policy_flags_by_id = candidates
        .iter()
        .map(|candidate| {
            (
                candidate.id.clone(),
                insight_policy_flags_for_candidate(candidate, &insights_by_id),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let claim_keys_by_id = candidates
        .iter()
        .map(|candidate| {
            (
                candidate.id.clone(),
                insight_claim_key_for_candidate(candidate, &insights_by_id),
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut ranked = candidates
        .iter()
        .enumerate()
        .map(|(idx, candidate)| {
            let signals = citation_source_signals(candidate);
            let envelope_score = if prefer_host_diversity {
                citation_single_snapshot_evidence_score(
                    candidate,
                    envelope_constraints,
                    envelope_policy,
                )
            } else {
                CandidateEvidenceScore::default()
            };
            (idx, signals, envelope_score)
        })
        .collect::<Vec<_>>();
    ranked.sort_by(
        |(left_idx, left_signals, left_envelope), (right_idx, right_signals, right_envelope)| {
            let left = &candidates[*left_idx];
            let right = &candidates[*right_idx];
            let insight_order = match (insights_by_id.get(&left.id), insights_by_id.get(&right.id))
            {
                (Some(left_insight), Some(right_insight)) => {
                    compare_weighted_insights_desc(left_insight, right_insight)
                }
                (Some(_), None) => std::cmp::Ordering::Less,
                (None, Some(_)) => std::cmp::Ordering::Greater,
                (None, None) => std::cmp::Ordering::Equal,
            };
            let envelope_order = if prefer_host_diversity {
                compare_candidate_evidence_scores_desc(left_envelope, right_envelope)
            } else {
                std::cmp::Ordering::Equal
            };
            let left_key = (
                left.from_successful_read,
                prefer_host_diversity
                    && envelope_score_resolves_constraint(envelope_constraints, left_envelope),
                citation_current_condition_metric_signal(left),
                citation_metric_signal(left),
                left_signals.official_status_host_hits > 0,
                left_signals.official_status_host_hits,
                left_signals.primary_status_surface_hits > 0,
                left_signals.primary_status_surface_hits,
                left_signals.secondary_coverage_hits == 0,
                left_signals.documentation_surface_hits == 0,
                citation_relevance_score(source, left),
                !citation_is_low_priority_coverage(left, *left_signals),
            );
            let right_key = (
                right.from_successful_read,
                prefer_host_diversity
                    && envelope_score_resolves_constraint(envelope_constraints, right_envelope),
                citation_current_condition_metric_signal(right),
                citation_metric_signal(right),
                right_signals.official_status_host_hits > 0,
                right_signals.official_status_host_hits,
                right_signals.primary_status_surface_hits > 0,
                right_signals.primary_status_surface_hits,
                right_signals.secondary_coverage_hits == 0,
                right_signals.documentation_surface_hits == 0,
                citation_relevance_score(source, right),
                !citation_is_low_priority_coverage(right, *right_signals),
            );
            insight_order
                .then_with(|| envelope_order)
                .then_with(|| right_key.cmp(&left_key))
        },
    );

    let hard_policy = derive_insight_hard_policy_gates(
        &ranked,
        candidates,
        &policy_flags_by_id,
        used_urls,
        citations_per_story,
        prefer_host_diversity,
        envelope_constraints,
    );
    let host_inventory = ranked
        .iter()
        .filter_map(|(idx, signals, envelope_score)| {
            let candidate = &candidates[*idx];
            if used_urls.contains(&candidate.url) || candidate.url.trim().is_empty() {
                return None;
            }
            let policy_flags = policy_flags_by_id
                .get(&candidate.id)
                .cloned()
                .unwrap_or_else(|| insight_policy_flags_for_candidate(candidate, &insights_by_id));
            if !candidate_passes_insight_hard_policy(
                candidate,
                *signals,
                envelope_score,
                hard_policy,
                envelope_constraints,
                &policy_flags,
            ) {
                return None;
            }
            source_host(&candidate.url)
        })
        .collect::<BTreeSet<_>>();
    let require_host_diversity =
        prefer_host_diversity && host_inventory.len() >= citations_per_story;

    let mut selected_ids = Vec::new();
    let mut selected_urls = BTreeSet::new();
    let mut selected_hosts = BTreeSet::new();
    let mut selected_claim_counts = BTreeMap::<String, usize>::new();

    // Keep story/citation alignment stable by anchoring to the story source URL first
    // when that URL exists in the citation candidate inventory.
    if selected_ids.len() < citations_per_story {
        if let Some(source_anchor_candidate) = candidates.iter().find(|candidate| {
            let candidate_url = candidate.url.trim();
            !candidate_url.is_empty()
                && !used_urls.contains(candidate_url)
                && url_structurally_equivalent(candidate_url, source.url.trim())
                && !selected_ids.iter().any(|id| id == &candidate.id)
        }) {
            selected_ids.push(source_anchor_candidate.id.clone());
            selected_urls.insert(source_anchor_candidate.url.clone());
            used_urls.insert(source_anchor_candidate.url.clone());
            if let Some(host) = source_host(&source_anchor_candidate.url) {
                selected_hosts.insert(host);
            }
            let claim_key =
                insight_claim_key_for_candidate(source_anchor_candidate, &insights_by_id);
            *selected_claim_counts.entry(claim_key).or_insert(0) += 1;
        }
    }

    let prefer_primary_backfill = ranked
        .iter()
        .any(|(idx, signals, _)| has_primary_status_candidate(*signals, &candidates[*idx]));
    run_insight_selection_pass(
        &ranked,
        candidates,
        &policy_flags_by_id,
        &claim_keys_by_id,
        used_urls,
        &mut selected_ids,
        &mut selected_urls,
        &mut selected_hosts,
        &mut selected_claim_counts,
        citations_per_story,
        1,
        require_host_diversity,
        false,
        prefer_primary_backfill,
        hard_policy,
        envelope_constraints,
    );
    if selected_ids.len() < citations_per_story {
        run_insight_selection_pass(
            &ranked,
            candidates,
            &policy_flags_by_id,
            &claim_keys_by_id,
            used_urls,
            &mut selected_ids,
            &mut selected_urls,
            &mut selected_hosts,
            &mut selected_claim_counts,
            citations_per_story,
            usize::MAX,
            false,
            false,
            false,
            hard_policy,
            envelope_constraints,
        );
    }
    if selected_ids.len() < citations_per_story {
        run_insight_selection_pass(
            &ranked,
            candidates,
            &policy_flags_by_id,
            &claim_keys_by_id,
            used_urls,
            &mut selected_ids,
            &mut selected_urls,
            &mut selected_hosts,
            &mut selected_claim_counts,
            citations_per_story,
            1,
            false,
            false,
            prefer_primary_backfill,
            hard_policy,
            envelope_constraints,
        );
    }
    if selected_ids.len() < citations_per_story {
        run_insight_selection_pass(
            &ranked,
            candidates,
            &policy_flags_by_id,
            &claim_keys_by_id,
            used_urls,
            &mut selected_ids,
            &mut selected_urls,
            &mut selected_hosts,
            &mut selected_claim_counts,
            citations_per_story,
            2,
            false,
            false,
            prefer_primary_backfill,
            hard_policy,
            envelope_constraints,
        );
    }
    if selected_ids.len() < citations_per_story {
        run_insight_selection_pass(
            &ranked,
            candidates,
            &policy_flags_by_id,
            &claim_keys_by_id,
            used_urls,
            &mut selected_ids,
            &mut selected_urls,
            &mut selected_hosts,
            &mut selected_claim_counts,
            citations_per_story,
            usize::MAX,
            false,
            false,
            prefer_primary_backfill,
            hard_policy,
            envelope_constraints,
        );
    }
    if selected_ids.len() < citations_per_story {
        run_insight_selection_pass(
            &ranked,
            candidates,
            &policy_flags_by_id,
            &claim_keys_by_id,
            used_urls,
            &mut selected_ids,
            &mut selected_urls,
            &mut selected_hosts,
            &mut selected_claim_counts,
            citations_per_story,
            usize::MAX,
            false,
            true,
            prefer_primary_backfill,
            hard_policy,
            envelope_constraints,
        );
    }
    if selected_ids.len() < citations_per_story {
        run_insight_selection_pass(
            &ranked,
            candidates,
            &policy_flags_by_id,
            &claim_keys_by_id,
            used_urls,
            &mut selected_ids,
            &mut selected_urls,
            &mut selected_hosts,
            &mut selected_claim_counts,
            citations_per_story,
            usize::MAX,
            false,
            true,
            false,
            hard_policy,
            envelope_constraints,
        );
    }

    selected_ids
}
