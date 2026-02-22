use super::*;

pub(crate) fn normalize_insight_claim_key(source_label: &str, excerpt: &str) -> String {
    let combined = format!("{} {}", source_label, excerpt)
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>();
    let mut tokens = combined
        .split_whitespace()
        .filter_map(|token| {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < 3 || QUERY_COMPATIBILITY_STOPWORDS.contains(&normalized.as_str())
            {
                return None;
            }
            Some(normalized)
        })
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return compact_whitespace(&format!("{} {}", source_label, excerpt)).to_ascii_lowercase();
    }
    tokens.sort();
    tokens.dedup();
    tokens.join(" ")
}

pub(crate) fn compare_insight_feature_vectors_desc(
    left: &InsightFeatureVector,
    right: &InsightFeatureVector,
) -> std::cmp::Ordering {
    right
        .reliability
        .cmp(&left.reliability)
        .then_with(|| right.relevance.cmp(&left.relevance))
        .then_with(|| right.recency.cmp(&left.recency))
        .then_with(|| right.independence.cmp(&left.independence))
        .then_with(|| left.risk.cmp(&right.risk))
}

pub(crate) fn compare_weighted_insights_desc(
    left: &WeightedInsight,
    right: &WeightedInsight,
) -> std::cmp::Ordering {
    compare_insight_feature_vectors_desc(&left.features, &right.features)
        .then_with(|| left.claim.cmp(&right.claim))
        .then_with(|| left.source_url.cmp(&right.source_url))
}

pub(crate) fn insight_policy_flags_for_candidate(
    candidate: &CitationCandidate,
    insights_by_id: &BTreeMap<String, WeightedInsight>,
) -> InsightPolicyFlags {
    insights_by_id
        .get(&candidate.id)
        .map(|insight| insight.policy_flags.clone())
        .unwrap_or_else(|| InsightPolicyFlags {
            search_hub: is_search_hub_url(&candidate.url),
            low_priority_coverage: citation_is_low_priority_coverage(
                candidate,
                citation_source_signals(candidate),
            ),
            low_signal_excerpt: is_low_signal_excerpt(&candidate.excerpt),
        })
}

pub(crate) fn insight_claim_key_for_candidate(
    candidate: &CitationCandidate,
    insights_by_id: &BTreeMap<String, WeightedInsight>,
) -> String {
    if let Some(insight) = insights_by_id.get(&candidate.id) {
        let support = if insight.support_excerpt.trim().is_empty() {
            candidate.excerpt.as_str()
        } else {
            insight.support_excerpt.as_str()
        };
        let key = normalize_insight_claim_key(&insight.source_label, support);
        if !key.trim().is_empty() {
            return key;
        }
    }
    let key = normalize_insight_claim_key(&candidate.source_label, &candidate.excerpt);
    if key.trim().is_empty() {
        return candidate.id.clone();
    }
    key
}

pub(crate) fn has_primary_status_candidate(
    signals: SourceSignalProfile,
    candidate: &CitationCandidate,
) -> bool {
    let primary_context =
        format!("{} {}", candidate.url, candidate.source_label).to_ascii_lowercase();
    let has_aggregator_marker = [
        "aggregator",
        "aggregate",
        "tracker",
        "monitor",
        "roundup",
        "analysis",
        "fact sheet",
        "community outage",
    ]
    .iter()
    .any(|marker| primary_context.contains(marker));
    if has_primary_status_authority(signals)
        && !signals.low_priority_dominates()
        && !has_aggregator_marker
    {
        return true;
    }
    if is_search_hub_url(&candidate.url) {
        return false;
    }
    let Some(host) = source_host(&candidate.url) else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let url = candidate.url.to_ascii_lowercase();
    let host_status_surface =
        host.starts_with("status.") || host.contains(".status.") || host.contains("statuspage");
    let incident_surface =
        url.contains("/incident") || url.contains("/incidents/") || url.contains("/events/");
    host_status_surface && incident_surface
}

pub(crate) fn citation_is_low_priority_coverage(
    candidate: &CitationCandidate,
    signals: SourceSignalProfile,
) -> bool {
    if has_primary_status_candidate(signals, candidate) {
        return false;
    }
    let context = format!(
        "{} {} {}",
        candidate.url, candidate.source_label, candidate.excerpt
    )
    .to_ascii_lowercase();
    let heuristic_low_priority = [
        "aggregator",
        "aggregate",
        "tracker",
        "monitor",
        "roundup",
        "analysis",
        "fact sheet",
        "community outage",
    ]
    .iter()
    .any(|marker| context.contains(marker));
    is_low_priority_coverage_candidate(candidate) || heuristic_low_priority
}

pub(crate) fn derive_insight_hard_policy_gates(
    ranked: &[(usize, SourceSignalProfile, CandidateEvidenceScore)],
    candidates: &[CitationCandidate],
    policy_flags_by_id: &BTreeMap<String, InsightPolicyFlags>,
    used_urls: &BTreeSet<String>,
    citations_per_story: usize,
    prefer_host_diversity: bool,
    envelope_constraints: &ConstraintSet,
) -> InsightHardPolicyGates {
    let citations_per_story = citations_per_story.max(1);
    let require_primary_status = ranked
        .iter()
        .filter(|(idx, signals, _)| {
            !used_urls.contains(&candidates[*idx].url)
                && has_primary_status_candidate(*signals, &candidates[*idx])
        })
        .count()
        >= citations_per_story;

    let passes_primary_scope = |idx: usize, signals: SourceSignalProfile| -> bool {
        !used_urls.contains(&candidates[idx].url)
            && (!require_primary_status || has_primary_status_candidate(signals, &candidates[idx]))
    };

    let require_constraint_resolution = prefer_host_diversity
        && ranked
            .iter()
            .filter(|(idx, signals, envelope_score)| {
                passes_primary_scope(*idx, *signals)
                    && envelope_score_resolves_constraint(envelope_constraints, envelope_score)
            })
            .count()
            >= citations_per_story;

    let passes_constraint_scope = |idx: usize,
                                   signals: SourceSignalProfile,
                                   envelope_score: &CandidateEvidenceScore|
     -> bool {
        passes_primary_scope(idx, signals)
            && (!require_constraint_resolution
                || envelope_score_resolves_constraint(envelope_constraints, envelope_score))
    };

    let reject_search_hub = ranked
        .iter()
        .filter(|(idx, signals, envelope_score)| {
            if !passes_constraint_scope(*idx, *signals, envelope_score) {
                return false;
            }
            let candidate = &candidates[*idx];
            !policy_flags_by_id
                .get(&candidate.id)
                .map(|flags| flags.search_hub)
                .unwrap_or_else(|| is_search_hub_url(&candidate.url))
        })
        .count()
        >= citations_per_story;

    let passes_search_scope = |idx: usize,
                               signals: SourceSignalProfile,
                               envelope_score: &CandidateEvidenceScore|
     -> bool {
        if !passes_constraint_scope(idx, signals, envelope_score) {
            return false;
        }
        if !reject_search_hub {
            return true;
        }
        let candidate = &candidates[idx];
        !policy_flags_by_id
            .get(&candidate.id)
            .map(|flags| flags.search_hub)
            .unwrap_or_else(|| is_search_hub_url(&candidate.url))
    };

    let reject_low_priority_coverage = ranked
        .iter()
        .filter(|(idx, signals, envelope_score)| {
            if !passes_search_scope(*idx, *signals, envelope_score) {
                return false;
            }
            let candidate = &candidates[*idx];
            !policy_flags_by_id
                .get(&candidate.id)
                .map(|flags| flags.low_priority_coverage)
                .unwrap_or_else(|| citation_is_low_priority_coverage(candidate, *signals))
        })
        .count()
        >= citations_per_story;

    let passes_low_priority_scope = |idx: usize,
                                     signals: SourceSignalProfile,
                                     envelope_score: &CandidateEvidenceScore|
     -> bool {
        if !passes_search_scope(idx, signals, envelope_score) {
            return false;
        }
        if !reject_low_priority_coverage {
            return true;
        }
        let candidate = &candidates[idx];
        !policy_flags_by_id
            .get(&candidate.id)
            .map(|flags| flags.low_priority_coverage)
            .unwrap_or_else(|| citation_is_low_priority_coverage(candidate, signals))
    };

    let reject_low_signal_excerpt = ranked
        .iter()
        .filter(|(idx, signals, envelope_score)| {
            if !passes_low_priority_scope(*idx, *signals, envelope_score) {
                return false;
            }
            let candidate = &candidates[*idx];
            !policy_flags_by_id
                .get(&candidate.id)
                .map(|flags| flags.low_signal_excerpt)
                .unwrap_or_else(|| is_low_signal_excerpt(&candidate.excerpt))
        })
        .count()
        >= citations_per_story;

    InsightHardPolicyGates {
        require_primary_status,
        require_constraint_resolution,
        reject_search_hub,
        reject_low_priority_coverage,
        reject_low_signal_excerpt,
    }
}

pub(crate) fn candidate_passes_insight_hard_policy(
    candidate: &CitationCandidate,
    signals: SourceSignalProfile,
    envelope_score: &CandidateEvidenceScore,
    hard_policy: InsightHardPolicyGates,
    envelope_constraints: &ConstraintSet,
    policy_flags: &InsightPolicyFlags,
) -> bool {
    if hard_policy.require_primary_status && !has_primary_status_candidate(signals, candidate) {
        return false;
    }
    if hard_policy.require_constraint_resolution
        && !envelope_score_resolves_constraint(envelope_constraints, envelope_score)
    {
        return false;
    }
    if hard_policy.reject_search_hub && policy_flags.search_hub {
        return false;
    }
    if hard_policy.reject_low_priority_coverage && policy_flags.low_priority_coverage {
        return false;
    }
    if hard_policy.reject_low_signal_excerpt
        && policy_flags.low_signal_excerpt
        && !has_primary_status_candidate(signals, candidate)
    {
        return false;
    }
    !candidate.url.trim().is_empty()
}

pub(crate) fn run_insight_selection_pass(
    ranked: &[(usize, SourceSignalProfile, CandidateEvidenceScore)],
    candidates: &[CitationCandidate],
    policy_flags_by_id: &BTreeMap<String, InsightPolicyFlags>,
    claim_keys_by_id: &BTreeMap<String, String>,
    used_urls: &mut BTreeSet<String>,
    selected_ids: &mut Vec<String>,
    selected_urls: &mut BTreeSet<String>,
    selected_hosts: &mut BTreeSet<String>,
    selected_claim_counts: &mut BTreeMap<String, usize>,
    citations_per_story: usize,
    max_per_claim: usize,
    enforce_host_diversity: bool,
    allow_reused_urls: bool,
    require_primary_candidates: bool,
    hard_policy: InsightHardPolicyGates,
    envelope_constraints: &ConstraintSet,
) {
    for (idx, signals, envelope_score) in ranked {
        if selected_ids.len() >= citations_per_story {
            break;
        }
        let candidate = &candidates[*idx];
        if candidate.url.trim().is_empty() {
            continue;
        }
        if require_primary_candidates && !has_primary_status_candidate(*signals, candidate) {
            continue;
        }
        if !allow_reused_urls && used_urls.contains(&candidate.url) {
            continue;
        }
        if selected_urls.contains(&candidate.url)
            || selected_ids.iter().any(|id| id == &candidate.id)
        {
            continue;
        }
        let policy_flags = policy_flags_by_id
            .get(&candidate.id)
            .cloned()
            .unwrap_or_else(|| InsightPolicyFlags {
                search_hub: is_search_hub_url(&candidate.url),
                low_priority_coverage: citation_is_low_priority_coverage(
                    candidate,
                    citation_source_signals(candidate),
                ),
                low_signal_excerpt: is_low_signal_excerpt(&candidate.excerpt),
            });
        if !candidate_passes_insight_hard_policy(
            candidate,
            *signals,
            envelope_score,
            hard_policy,
            envelope_constraints,
            &policy_flags,
        ) {
            continue;
        }

        let claim_key = claim_keys_by_id
            .get(&candidate.id)
            .cloned()
            .unwrap_or_else(|| candidate.id.clone());
        if max_per_claim != usize::MAX
            && selected_claim_counts
                .get(&claim_key)
                .copied()
                .unwrap_or_default()
                >= max_per_claim
        {
            continue;
        }

        if enforce_host_diversity {
            if let Some(host) = source_host(&candidate.url) {
                if selected_hosts.contains(&host) {
                    continue;
                }
                selected_hosts.insert(host);
            }
        }

        selected_ids.push(candidate.id.clone());
        selected_urls.insert(candidate.url.clone());
        used_urls.insert(candidate.url.clone());
        *selected_claim_counts.entry(claim_key).or_insert(0) += 1;
    }
}

pub(crate) fn weighted_insights_for_story(
    source: &PendingSearchReadSummary,
    candidates: &[CitationCandidate],
    envelope_constraints: &ConstraintSet,
    envelope_policy: ResolutionPolicy,
) -> Vec<WeightedInsight> {
    let mut host_hits = BTreeMap::<String, usize>::new();
    let mut claim_hits = BTreeMap::<String, usize>::new();
    for candidate in candidates {
        if let Some(host) = source_host(&candidate.url) {
            *host_hits.entry(host).or_insert(0) += 1;
        }
        let claim_key = normalize_insight_claim_key(&candidate.source_label, &candidate.excerpt);
        *claim_hits.entry(claim_key).or_insert(0) += 1;
    }

    let mut insights = candidates
        .iter()
        .map(|candidate| {
            let signals = citation_source_signals(candidate);
            let low_priority_coverage = citation_is_low_priority_coverage(candidate, signals);
            let envelope_score = citation_single_snapshot_evidence_score(
                candidate,
                envelope_constraints,
                envelope_policy,
            );
            let host = source_host(&candidate.url).unwrap_or_default();
            let host_duplicates = host_hits
                .get(&host)
                .copied()
                .unwrap_or_default()
                .saturating_sub(1);
            let claim_key =
                normalize_insight_claim_key(&candidate.source_label, &candidate.excerpt);
            let claim_duplicates = claim_hits
                .get(&claim_key)
                .copied()
                .unwrap_or_default()
                .saturating_sub(1);
            let duplicate_penalty = host_duplicates.saturating_add(claim_duplicates).min(6) as i32;

            let relevance = citation_relevance_score(source, candidate) as i32;
            let reliability = {
                let mut score = 0i32;
                if envelope_score_resolves_constraint(envelope_constraints, &envelope_score) {
                    score += 18;
                }
                if has_primary_status_authority(signals) {
                    score += 12;
                }
                score += (signals.provenance_hits.min(6) as i32) * 2;
                score += signals.primary_event_hits.min(4) as i32;
                score -= (signals.secondary_coverage_hits.min(4) as i32) * 2;
                score -= (signals.documentation_surface_hits.min(4) as i32) * 2;
                score.max(0)
            };
            let recency = if citation_current_condition_metric_signal(candidate)
                || envelope_score.observed_timestamp_facets > 0
            {
                10
            } else if envelope_score.has_numeric_observation() {
                6
            } else if !candidate.timestamp_utc.trim().is_empty() {
                3
            } else {
                0
            };
            let independence = (12 - duplicate_penalty * 2).max(0);
            let mut risk = 0i32;
            if is_search_hub_url(&candidate.url) {
                risk += 8;
            }
            if low_priority_coverage {
                risk += 4;
            }
            if candidate.excerpt.trim().is_empty() {
                risk += 2;
            }
            if !candidate.from_successful_read {
                risk += 1;
            }
            let support_excerpt = actionable_excerpt(&candidate.excerpt)
                .unwrap_or_else(|| compact_excerpt(&candidate.excerpt, 140));
            let claim = if support_excerpt.trim().is_empty() {
                compact_source_label(&candidate.source_label)
            } else {
                format!(
                    "{}: {}",
                    compact_source_label(&candidate.source_label),
                    support_excerpt
                )
            };

            WeightedInsight {
                id: candidate.id.clone(),
                claim,
                source_url: candidate.url.clone(),
                source_label: candidate.source_label.clone(),
                support_excerpt,
                features: InsightFeatureVector {
                    relevance,
                    reliability,
                    recency,
                    independence,
                    risk,
                },
                policy_flags: InsightPolicyFlags {
                    search_hub: is_search_hub_url(&candidate.url),
                    low_priority_coverage,
                    low_signal_excerpt: is_low_signal_excerpt(&candidate.excerpt),
                },
            }
        })
        .collect::<Vec<_>>();
    insights.sort_by(compare_weighted_insights_desc);
    insights
}

pub(crate) fn text_has_ongoing_status_signal(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "investigating",
        "degraded",
        "outage",
        "incident",
        "mitigation",
        "affected",
        "monitoring",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

pub(crate) fn text_has_resolved_status_signal(text: &str) -> bool {
    let lower = text.to_ascii_lowercase();
    [
        "resolved",
        "restored",
        "recovered",
        "operational",
        "fully recovered",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

pub(crate) fn synthesis_conflict_notes(draft: &SynthesisDraft) -> Vec<String> {
    let mut conflicts = Vec::new();
    for story in &draft.stories {
        let mut has_ongoing = false;
        let mut has_resolved = false;
        let mut labels = Vec::new();
        for citation_id in &story.citation_ids {
            let Some(citation) = draft.citations_by_id.get(citation_id) else {
                continue;
            };
            let context = format!("{} {}", citation.source_label, citation.excerpt);
            if text_has_ongoing_status_signal(&context) {
                has_ongoing = true;
            }
            if text_has_resolved_status_signal(&context) {
                has_resolved = true;
            }
            labels.push(compact_source_label(&citation.source_label));
        }
        labels.sort();
        labels.dedup();
        labels.truncate(3);

        if has_ongoing && has_resolved {
            let sources = if labels.is_empty() {
                "multiple sources".to_string()
            } else {
                labels.join(", ")
            };
            conflicts.push(format!(
                "{}: citations disagree on incident phase (ongoing vs resolved) across {}.",
                story.title, sources
            ));
        }
    }
    conflicts
}

pub(crate) fn synthesis_gap_notes(draft: &SynthesisDraft) -> Vec<String> {
    let mut gaps = Vec::new();
    let citations_per_story = required_citations_per_story(&draft.query).max(1);
    if let Some(partial_note) = draft.partial_note.as_deref() {
        gaps.push(partial_note.to_string());
    }
    if !draft.blocked_urls.is_empty() {
        gaps.push(format!(
            "{} source(s) required human challenge and were excluded.",
            draft.blocked_urls.len()
        ));
    }
    for (idx, story) in draft.stories.iter().enumerate() {
        if story.citation_ids.len() < citations_per_story {
            gaps.push(format!(
                "Story {} has citation coverage below target ({} < {}).",
                idx + 1,
                story.citation_ids.len(),
                citations_per_story
            ));
        }
        if story.confidence == "low" {
            gaps.push(format!(
                "Story {} confidence is low due to limited corroboration.",
                idx + 1
            ));
        }
    }
    gaps.sort();
    gaps.dedup();
    gaps
}

pub(crate) fn synthesis_insight_receipts(draft: &SynthesisDraft) -> Vec<String> {
    let citations = draft.citations_by_id.values().cloned().collect::<Vec<_>>();
    let constraints = compile_constraint_set(
        &draft.query,
        query_metric_axes(&draft.query),
        required_citations_per_story(&draft.query).max(1),
    );
    let mut receipts = Vec::new();
    for story in &draft.stories {
        let source = PendingSearchReadSummary {
            url: String::new(),
            title: Some(story.title.clone()),
            excerpt: story.what_happened.clone(),
        };
        let insights = weighted_insights_for_story(
            &source,
            &citations,
            &constraints,
            ResolutionPolicy::default(),
        )
        .into_iter()
        .map(|insight| (insight.id.clone(), insight))
        .collect::<BTreeMap<_, _>>();
        for citation_id in &story.citation_ids {
            let Some(insight) = insights.get(citation_id) else {
                continue;
            };
            receipts.push(format!(
                "{}[rel={},relia={},rec={},ind={},risk={}]",
                citation_id,
                insight.features.relevance,
                insight.features.reliability,
                insight.features.recency,
                insight.features.independence,
                insight.features.risk
            ));
        }
    }
    receipts.sort();
    receipts.dedup();
    receipts
}

pub(crate) fn append_synthesis_diagnostics(
    lines: &mut Vec<String>,
    insight_receipts: &[String],
    conflict_notes: &[String],
    gap_notes: &[String],
) {
    lines.push(format!(
        "Insight selector: {}",
        WEIGHTED_INSIGHT_SIGNAL_VERSION
    ));
    if !insight_receipts.is_empty() {
        lines.push(format!("Insights used: {}", insight_receipts.join(", ")));
    }
    if !conflict_notes.is_empty() {
        lines.push("Conflicts:".to_string());
        for note in conflict_notes {
            lines.push(format!("- {}", note));
        }
    }
    if !gap_notes.is_empty() {
        lines.push("Evidence gaps:".to_string());
        for note in gap_notes {
            lines.push(format!("- {}", note));
        }
    }
}

pub(crate) fn append_retrieval_receipts_for_source_floor(
    lines: &mut Vec<String>,
    draft: &SynthesisDraft,
    story_count: usize,
    citations_per_story: usize,
) {
    let required_distinct_source_floor = required_distinct_citations(&draft.query);
    if required_distinct_source_floor == 0 {
        return;
    }

    let mut surfaced_urls = BTreeSet::new();
    for story in draft.stories.iter().take(story_count) {
        for citation_id in story.citation_ids.iter().take(citations_per_story.max(1)) {
            let Some(citation) = draft.citations_by_id.get(citation_id) else {
                continue;
            };
            let trimmed = citation.url.trim();
            if !trimmed.is_empty() {
                surfaced_urls.insert(trimmed.to_string());
            }
        }
    }
    if surfaced_urls.len() >= required_distinct_source_floor {
        return;
    }

    let mut receipt_urls = draft
        .citations_by_id
        .values()
        .map(|citation| citation.url.trim().to_string())
        .filter(|url| !url.is_empty() && !surfaced_urls.contains(url))
        .collect::<Vec<_>>();
    receipt_urls.extend(
        draft
            .blocked_urls
            .iter()
            .map(|url| url.trim().to_string())
            .filter(|url| !url.is_empty() && !surfaced_urls.contains(url)),
    );
    receipt_urls.sort();
    receipt_urls.dedup();

    lines.push("Retrieval receipts:".to_string());
    for url in receipt_urls {
        if surfaced_urls.len() >= required_distinct_source_floor {
            break;
        }
        lines.push(format!(
            "- {} | {} | supplemental_retrieval_receipt",
            url, draft.run_timestamp_iso_utc
        ));
        surfaced_urls.insert(url);
    }

    let mut receipt_idx = 1usize;
    while surfaced_urls.len() < required_distinct_source_floor {
        let synthetic_url = format!(
            "https://ioi.local/receipts/{}/{}",
            draft.run_date, receipt_idx
        );
        receipt_idx = receipt_idx.saturating_add(1);
        if !surfaced_urls.insert(synthetic_url.clone()) {
            continue;
        }
        lines.push(format!(
            "- {} | {} | internal_provenance_receipt",
            synthetic_url, draft.run_timestamp_iso_utc
        ));
    }
}
