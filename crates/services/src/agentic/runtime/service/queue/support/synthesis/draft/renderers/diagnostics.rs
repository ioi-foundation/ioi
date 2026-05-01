use super::*;

pub(super) struct MultiStoryGroundingAssessment {
    pub(super) insufficient_multi_story_grounding: bool,
    pub(super) actionable_read_grounding_count: usize,
    pub(super) required_distinct_source_floor: usize,
    pub(super) shared_story_topic_count: usize,
    pub(super) story_citation_floor: usize,
}

pub(super) fn assess_multi_story_grounding(
    draft: &SynthesisDraft,
    story_count: usize,
    citations_per_story: usize,
    headline_lookup_mode: bool,
    use_single_snapshot_layout: bool,
) -> MultiStoryGroundingAssessment {
    let retrieval_contract = draft.retrieval_contract.as_ref();
    let required_distinct_source_floor = story_count.max(1);
    let actionable_read_grounding_sources = draft
        .citations_by_id
        .values()
        .filter(|citation| {
            citation_usable_url(&citation.url, headline_lookup_mode)
                && if headline_lookup_mode {
                    excerpt_has_claim_signal(&citation.excerpt)
                        || !is_low_signal_title(&citation.source_label)
                } else {
                    excerpt_has_query_grounding_signal_with_contract(
                        retrieval_contract,
                        &draft.query,
                        required_distinct_source_floor,
                        &citation.url,
                        &citation.source_label,
                        &citation.excerpt,
                    )
                }
        })
        .filter_map(|citation| {
            citation_source_independence_key_for_query(retrieval_contract, &draft.query, citation)
        })
        .collect::<BTreeSet<_>>();
    let actionable_read_grounding_count = actionable_read_grounding_sources.len();
    let has_read_grounding = actionable_read_grounding_count > 0;
    let story_citation_floor = citations_per_story.max(1);
    let complete_story_slots = draft
        .stories
        .iter()
        .take(story_count)
        .filter(|story| {
            story
                .citation_ids
                .iter()
                .take(story_citation_floor)
                .filter_map(|citation_id| draft.citations_by_id.get(citation_id))
                .filter(|citation| citation_usable_url(&citation.url, headline_lookup_mode))
                .count()
                >= story_citation_floor
        })
        .count();
    let has_story_slot_floor = draft.stories.len() >= story_count;
    let has_story_coverage_floor = complete_story_slots >= story_count;
    let has_distinct_source_floor =
        actionable_read_grounding_count >= required_distinct_source_floor;
    let has_primary_status_inventory = draft.citations_by_id.values().any(|citation| {
        has_primary_status_authority(analyze_source_record_signals(
            &citation.url,
            &citation.source_label,
            &citation.excerpt,
        ))
    });
    let headline_shared_story_anchor_tokens = if headline_lookup_mode {
        headline_story_shared_anchor_tokens(&draft.stories, story_count)
    } else {
        BTreeSet::new()
    };
    let insufficient_multi_story_grounding = !use_single_snapshot_layout
        && story_count > 1
        && (!has_story_slot_floor
            || !has_story_coverage_floor
            || !has_distinct_source_floor
            || (!has_read_grounding && !has_primary_status_inventory));

    MultiStoryGroundingAssessment {
        insufficient_multi_story_grounding,
        actionable_read_grounding_count,
        required_distinct_source_floor,
        shared_story_topic_count: headline_shared_story_anchor_tokens.len(),
        story_citation_floor,
    }
}

pub(super) fn render_insufficient_multi_story_floor(
    draft: &SynthesisDraft,
    story_count: usize,
    citations_per_story: usize,
    headline_lookup_mode: bool,
    assessment: &MultiStoryGroundingAssessment,
    insight_receipts: &[String],
    conflict_notes: &[String],
    gap_notes: &[String],
) -> String {
    let mut lines = vec![summary_heading(draft), String::new()];
    lines.push(format!(
        "Synthesis unavailable: multi-story evidence floor unmet (stories={} of {}, citations_per_story={}, distinct_actionable_sources={} of {}, shared_story_topics={}).",
        draft.stories.len().min(story_count),
        story_count,
        assessment.story_citation_floor,
        assessment.actionable_read_grounding_count,
        assessment.required_distinct_source_floor,
        assessment.shared_story_topic_count
    ));

    let mut used_story_urls = BTreeSet::new();
    for (idx, story) in draft
        .stories
        .iter()
        .take(story_count.max(1).min(draft.stories.len()))
        .enumerate()
    {
        lines.push(String::new());
        lines.push(format!("Story {}: {}", idx + 1, story.title));
        lines.push(format!("What happened: {}", story.what_happened));
        lines.push("Citations:".to_string());

        let mut emitted = 0usize;
        let mut seen_story_urls = BTreeSet::new();
        for citation_id in story
            .citation_ids
            .iter()
            .take(assessment.story_citation_floor.max(1))
        {
            let Some(citation) = draft.citations_by_id.get(citation_id) else {
                continue;
            };
            if !citation_usable_url(&citation.url, headline_lookup_mode) {
                continue;
            }
            if !seen_story_urls.insert(citation.url.clone()) {
                continue;
            }
            used_story_urls.insert(citation.url.clone());
            lines.push(format!(
                "- {} | {} | {} | {}",
                citation.source_label, citation.url, citation.timestamp_utc, citation.note
            ));
            emitted += 1;
        }
        if emitted == 0 {
            lines.push("- No citable evidence was captured for this story slot.".to_string());
        }
        lines.push(format!("Confidence: {}", story.confidence));
        lines.push(format!("Caveat: {}", story.caveat));
    }

    let mut candidate_citations = draft
        .citations_by_id
        .values()
        .filter(|citation| citation_usable_url(&citation.url, headline_lookup_mode))
        .cloned()
        .collect::<Vec<_>>();
    candidate_citations.sort_by(|left, right| left.url.cmp(&right.url));
    candidate_citations.dedup_by(|left, right| left.url == right.url);
    if !candidate_citations.is_empty() {
        let additional_candidates = candidate_citations
            .into_iter()
            .filter(|citation| !used_story_urls.contains(&citation.url))
            .collect::<Vec<_>>();
        if !additional_candidates.is_empty() {
            lines.push("Candidate sources (metadata-only):".to_string());
            for citation in &additional_candidates {
                lines.push(format!(
                    "- {} | {} | {} | {}",
                    citation.source_label, citation.url, citation.timestamp_utc, citation.note
                ));
            }
        }
    }

    append_common_postamble(
        &mut lines,
        draft,
        story_count,
        citations_per_story,
        insight_receipts,
        conflict_notes,
        gap_notes,
        Some("low"),
    );
    lines.join("\n")
}

fn headline_story_topic_tokens(input: &str) -> BTreeSet<String> {
    const STORY_TOPIC_STOPWORDS: &[&str] = &[
        "the",
        "and",
        "for",
        "with",
        "that",
        "this",
        "from",
        "into",
        "what",
        "happened",
        "story",
        "stories",
        "today",
        "top",
        "news",
        "headline",
        "headlines",
        "breaking",
        "latest",
        "update",
        "updates",
        "report",
        "reports",
        "source",
        "sources",
        "evidence",
        "media",
        "coverage",
        "live",
        "as",
        "of",
        "run",
        "timestamp",
        "utc",
        "us",
        "u",
        "s",
    ];
    input
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .filter_map(|token| {
            let normalized = token.trim();
            if normalized.len() < 3 {
                return None;
            }
            if normalized.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            if STORY_TOPIC_STOPWORDS.contains(&normalized) {
                return None;
            }
            Some(normalized.to_string())
        })
        .collect()
}

fn headline_story_shared_anchor_tokens(
    stories: &[StoryDraft],
    story_count: usize,
) -> BTreeSet<String> {
    let mut sets = stories
        .iter()
        .take(story_count)
        .map(|story| {
            headline_story_topic_tokens(&format!("{} {}", story.title, story.what_happened))
        })
        .filter(|tokens| !tokens.is_empty())
        .collect::<Vec<_>>();
    if sets.len() < story_count {
        return BTreeSet::new();
    }
    let mut shared = sets.remove(0);
    for tokens in sets {
        shared = shared
            .intersection(&tokens)
            .cloned()
            .collect::<BTreeSet<_>>();
        if shared.is_empty() {
            break;
        }
    }
    shared
}

fn citation_source_independence_key_for_query(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query: &str,
    citation: &CitationCandidate,
) -> Option<String> {
    let trimmed = citation.url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if retrieval_contract_entity_diversity_required(retrieval_contract, query) {
        let locality_hint = explicit_query_scope_hint(query).or_else(|| {
            retrieval_contract_requires_runtime_locality(retrieval_contract, query)
                .then(|| effective_locality_scope_hint(None))
                .flatten()
        });
        let source = PendingSearchReadSummary {
            url: citation.url.clone(),
            title: Some(citation.source_label.clone()),
            excerpt: citation.excerpt.clone(),
        };
        if let Some(target_name) =
            local_business_target_name_from_source(&source, locality_hint.as_deref())
                .and_then(|name| normalized_local_business_target_name(&name))
        {
            return Some(target_name);
        }
    }
    let signals = analyze_source_record_signals(trimmed, &citation.source_label, &citation.excerpt);
    if has_primary_status_authority(signals) {
        if let Ok(parsed) = Url::parse(trimmed) {
            let path = parsed.path().trim_matches('/').to_ascii_lowercase();
            if !path.is_empty() {
                if let Some(host) = parsed.host_str() {
                    let normalized_host =
                        host.trim().trim_start_matches("www.").to_ascii_lowercase();
                    if !normalized_host.is_empty() {
                        return Some(format!("{normalized_host}/{path}"));
                    }
                }
            }
        }
    }
    if let Some(host) = source_host(trimmed) {
        return Some(host.strip_prefix("www.").unwrap_or(&host).to_string());
    }
    Some(trimmed.to_ascii_lowercase())
}

pub(super) fn citation_usable_url(url: &str, headline_lookup_mode: bool) -> bool {
    let trimmed = url.trim();
    if trimmed.is_empty() || !is_citable_web_url(trimmed) {
        return false;
    }
    if headline_lookup_mode {
        !is_search_hub_url(trimmed) && !is_multi_item_listing_url(trimmed)
    } else {
        !is_search_hub_url(trimmed)
    }
}
