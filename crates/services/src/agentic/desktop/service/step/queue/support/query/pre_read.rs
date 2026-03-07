use super::*;
use ioi_types::app::agentic::WebRetrievalContract;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RetrievalAffordanceKind {
    DirectCitationRead,
    DiscoveryExpansionSeedRead,
}

impl RetrievalAffordanceKind {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::DirectCitationRead => "direct_citation_read",
            Self::DiscoveryExpansionSeedRead => "discovery_expansion_seed_read",
        }
    }
}

fn looks_like_deep_article_url(raw: &str) -> bool {
    let trimmed = raw.trim();
    if trimmed.is_empty() || is_search_hub_url(trimmed) {
        return false;
    }
    let Ok(parsed) = Url::parse(trimmed) else {
        return false;
    };
    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return false;
    }
    let Some(host) = parsed.host_str() else {
        return false;
    };
    if host.trim().is_empty() {
        return false;
    }
    if host.eq_ignore_ascii_case("news.google.com")
        && parsed
            .path()
            .to_ascii_lowercase()
            .starts_with("/rss/articles/")
    {
        return true;
    }

    let normalized_path = parsed.path().trim_matches('/').to_ascii_lowercase();
    if normalized_path.is_empty() {
        return false;
    }
    let segments = normalized_path
        .split('/')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    if segments.is_empty() {
        return false;
    }
    if segments.len() <= 2
        && segments
            .first()
            .copied()
            .map(|segment| {
                matches!(
                    segment,
                    "show" | "shows" | "watch" | "video" | "videos" | "live" | "tv"
                )
            })
            .unwrap_or(false)
    {
        return false;
    }

    let path_hub_markers = [
        "news",
        "latest",
        "home",
        "homepage",
        "index",
        "index.html",
        "video",
        "videos",
        "live",
        "world",
        "us",
        "top-stories",
        "top-news",
    ];
    let marker_segment = |segment: &str| {
        if segment.is_empty() {
            return false;
        }
        if path_hub_markers.contains(&segment) {
            return true;
        }
        segment
            .split('-')
            .all(|token| !token.is_empty() && path_hub_markers.contains(&token))
    };
    if segments.len() <= 2 && segments.iter().all(|segment| marker_segment(segment)) {
        return false;
    }

    let last_segment = segments.last().copied().unwrap_or_default();
    let slug_segments = last_segment
        .split('-')
        .filter(|segment| !segment.trim().is_empty())
        .collect::<Vec<_>>();
    if slug_segments.len() >= 3 {
        return true;
    }
    if segments.len() >= 2 {
        let penultimate_segment = segments[segments.len() - 2];
        let penultimate_slug_segments = penultimate_segment
            .split('-')
            .filter(|segment| !segment.trim().is_empty())
            .collect::<Vec<_>>();
        let trailing_id_like = last_segment.chars().any(|ch| ch.is_ascii_digit())
            || last_segment
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'));
        if penultimate_slug_segments.len() >= 3 && trailing_id_like {
            return true;
        }
    }

    let has_deep_path = segments.len() >= 3;
    let has_article_marker = segments.iter().any(|segment| {
        segment.chars().any(|ch| ch.is_ascii_digit())
            || segment.contains("article")
            || segment.contains("story")
            || segment.contains("feature")
            || segment.contains("update")
    });
    has_deep_path && has_article_marker
}

fn source_url_from_metadata_excerpt(excerpt: &str) -> Option<String> {
    let marker = "source_url=";
    let lower = excerpt.to_ascii_lowercase();
    let start = lower.find(marker)? + marker.len();
    let candidate = excerpt
        .get(start..)?
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .trim_matches(|ch: char| "|,;:!?)]}\"'".contains(ch))
        .trim();
    if candidate.starts_with("http://") || candidate.starts_with("https://") {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn source_domain_key_from_metadata_excerpt(excerpt: &str) -> Option<String> {
    source_url_from_metadata_excerpt(excerpt).and_then(|candidate| canonical_domain_key(&candidate))
}

fn candidate_distinct_domain_key_from_excerpt(url: &str, excerpt: &str) -> Option<String> {
    let url_domain = canonical_domain_key(url);
    let hinted_domain = source_domain_key_from_metadata_excerpt(excerpt);
    match (url_domain, hinted_domain) {
        (Some(url_domain), Some(hinted_domain)) if url_domain != hinted_domain => {
            Some(hinted_domain)
        }
        (Some(url_domain), _) => Some(url_domain),
        (None, Some(hinted_domain)) => Some(hinted_domain),
        (None, None) => None,
    }
}

pub(crate) fn projection_candidate_url_allowed(raw: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.is_empty()
        && is_citable_web_url(trimmed)
        && !is_search_hub_url(trimmed)
        && !is_multi_item_listing_url(trimmed)
        && looks_like_deep_article_url(trimmed)
}

fn single_snapshot_metric_detail_candidate_allowed_with_contract_and_projection(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if !retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, query_contract) {
        return false;
    }

    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !is_citable_web_url(trimmed)
        || is_search_hub_url(trimmed)
        || is_multi_item_listing_url(trimmed)
    {
        return false;
    }
    if title.trim().is_empty() && excerpt.trim().is_empty() {
        return false;
    }
    if source_has_human_challenge_signal(trimmed, title, excerpt) {
        return false;
    }

    let compatibility = candidate_constraint_compatibility(
        &projection.constraints,
        &projection.query_facets,
        &projection.query_native_tokens,
        &projection.query_tokens,
        &projection.locality_tokens,
        projection.locality_scope.is_some(),
        trimmed,
        title,
        excerpt,
    );
    let resolvable_payload = candidate_time_sensitive_resolvable_payload(raw, title, excerpt);
    let score = single_snapshot_candidate_envelope_score(
        &projection.constraints,
        ResolutionPolicy::default(),
        trimmed,
        title,
        excerpt,
    );

    compatibility_passes_projection(projection, &compatibility)
        && (resolvable_payload
            || envelope_score_resolves_constraint(&projection.constraints, &score))
}

fn single_snapshot_metric_detail_candidate_allowed_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    single_snapshot_metric_detail_candidate_allowed_with_contract_and_projection(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

fn local_business_detail_root_candidate_allowed_with_contract(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if !retrieval_contract_prefers_multi_item_cardinality(retrieval_contract, query_contract)
        || !retrieval_contract_requests_comparison(retrieval_contract, query_contract)
        || !projection.query_facets.locality_sensitive_public_fact
        || !projection.query_facets.grounded_external_required
        || projection.locality_scope.is_none()
    {
        return false;
    }

    let trimmed = raw.trim();
    if trimmed.is_empty() || !is_citable_web_url(trimmed) || is_search_hub_url(trimmed) {
        return false;
    }
    let Ok(parsed) = Url::parse(trimmed) else {
        return false;
    };
    if !parsed.path().trim_matches('/').is_empty() {
        return false;
    }
    if title.trim().is_empty() && excerpt.trim().is_empty() {
        return false;
    }
    if source_has_human_challenge_signal(trimmed, title, excerpt) {
        return false;
    }

    let compatibility = candidate_constraint_compatibility(
        &projection.constraints,
        &projection.query_facets,
        &projection.query_native_tokens,
        &projection.query_tokens,
        &projection.locality_tokens,
        projection.locality_scope.is_some(),
        trimmed,
        title,
        excerpt,
    );
    let discovery_compatible = compatibility_passes_projection(projection, &compatibility)
        || (projection.locality_scope.is_some()
            && projection.query_facets.locality_sensitive_public_fact
            && compatibility.is_compatible);
    if !discovery_compatible {
        return false;
    }

    let host_compact = parsed
        .host_str()
        .unwrap_or_default()
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    let source_tokens = normalized_anchor_tokens(&format!("{} {}", title, excerpt));
    let host_aligns_with_source = source_tokens.iter().any(|token| {
        token.len() >= 4
            && !projection.locality_tokens.contains(token)
            && host_compact.contains(token)
    });
    if !host_aligns_with_source {
        return false;
    }

    let signals = analyze_source_record_signals(trimmed, title, excerpt);
    !(signals.low_priority_hits > 0 || signals.low_priority_dominates())
}

fn local_business_detail_root_candidate_allowed(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    local_business_detail_root_candidate_allowed_with_contract(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

fn local_business_discovery_seed_required_with_contract(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
) -> bool {
    retrieval_contract_entity_diversity_required(retrieval_contract, query_contract)
        && projection.query_facets.locality_sensitive_public_fact
        && projection.query_facets.grounded_external_required
        && projection.locality_scope.is_some()
        && projection.enforce_grounded_compatibility()
}

fn local_business_discovery_seed_required(
    query_contract: &str,
    projection: &QueryConstraintProjection,
) -> bool {
    local_business_discovery_seed_required_with_contract(None, query_contract, projection)
}

fn local_business_direct_citation_source_allowed_with_contract_and_projection(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if !retrieval_contract_entity_diversity_required(retrieval_contract, query_contract)
        || !retrieval_contract_prefers_multi_item_cardinality(retrieval_contract, query_contract)
        || !retrieval_contract_requests_comparison(retrieval_contract, query_contract)
        || !projection.query_facets.locality_sensitive_public_fact
        || !projection.query_facets.grounded_external_required
        || projection.locality_scope.is_none()
    {
        return true;
    }

    let source = PendingSearchReadSummary {
        url: raw.trim().to_string(),
        title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
        excerpt: excerpt.trim().to_string(),
    };
    if local_business_target_name_from_source(&source, projection.locality_scope.as_deref())
        .is_some()
    {
        return true;
    }

    local_business_detail_root_candidate_allowed_with_contract(
        retrieval_contract,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

fn local_business_direct_citation_source_allowed_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    local_business_direct_citation_source_allowed_with_contract_and_projection(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

fn grounded_direct_citation_source_allowed_with_contract_and_projection(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if !projection.enforce_grounded_compatibility() {
        return true;
    }

    let trimmed = raw.trim();
    if trimmed.is_empty() || title.trim().is_empty() && excerpt.trim().is_empty() {
        return false;
    }
    if source_has_human_challenge_signal(trimmed, title, excerpt) {
        return false;
    }

    let signals = analyze_source_record_signals(trimmed, title, excerpt);
    if signals.low_priority_hits > 0 || signals.low_priority_dominates() {
        return false;
    }

    let compatibility = candidate_constraint_compatibility(
        &projection.constraints,
        &projection.query_facets,
        &projection.query_native_tokens,
        &projection.query_tokens,
        &projection.locality_tokens,
        projection.locality_scope.is_some(),
        trimmed,
        title,
        excerpt,
    );
    if !compatibility_passes_projection(projection, &compatibility) {
        return false;
    }

    if retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, query_contract)
        && !candidate_time_sensitive_resolvable_payload(trimmed, title, excerpt)
    {
        return false;
    }

    true
}

fn grounded_direct_citation_source_allowed_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    grounded_direct_citation_source_allowed_with_contract_and_projection(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

pub(crate) fn projection_candidate_url_allowed_with_contract_and_projection(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if projection_candidate_listing_disallowed_with_contract_and_projection(
        retrieval_contract,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    ) {
        return false;
    }
    let candidate_allowed = projection_candidate_url_allowed(raw)
        || single_snapshot_metric_detail_candidate_allowed_with_contract_and_projection(
            retrieval_contract,
            query_contract,
            projection,
            raw,
            title,
            excerpt,
        )
        || local_business_detail_root_candidate_allowed_with_contract(
            retrieval_contract,
            query_contract,
            projection,
            raw,
            title,
            excerpt,
        );
    if !candidate_allowed {
        return false;
    }
    if !local_business_direct_citation_source_allowed_with_contract_and_projection(
        retrieval_contract,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    ) {
        return false;
    }
    if !grounded_direct_citation_source_allowed_with_contract_and_projection(
        retrieval_contract,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    ) {
        return false;
    }
    true
}

pub(crate) fn projection_candidate_url_allowed_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    projection_candidate_url_allowed_with_contract_and_projection(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

pub(crate) fn local_business_discovery_source_allowed_with_contract_and_projection(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if projection_candidate_url_allowed_with_contract_and_projection(
        retrieval_contract,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    ) {
        return true;
    }
    if !local_business_discovery_seed_required_with_contract(
        retrieval_contract,
        query_contract,
        projection,
    ) {
        return false;
    }

    let trimmed = raw.trim();
    if trimmed.is_empty() || !is_citable_web_url(trimmed) || is_search_hub_url(trimmed) {
        return false;
    }
    let Ok(parsed) = Url::parse(trimmed) else {
        return false;
    };
    if parsed.path().trim_matches('/').is_empty() {
        return false;
    }
    if title.trim().is_empty() && excerpt.trim().is_empty() {
        return false;
    }
    if source_has_human_challenge_signal(trimmed, title, excerpt) {
        return false;
    }
    if !is_multi_item_listing_url(trimmed)
        && !local_business_collection_surface_candidate(
            projection.locality_scope.as_deref(),
            trimmed,
            title,
            excerpt,
        )
    {
        return false;
    }

    let compatibility = candidate_constraint_compatibility(
        &projection.constraints,
        &projection.query_facets,
        &projection.query_native_tokens,
        &projection.query_tokens,
        &projection.locality_tokens,
        projection.locality_scope.is_some(),
        trimmed,
        title,
        excerpt,
    );
    if !compatibility_passes_projection(projection, &compatibility) {
        return false;
    }

    let signals = analyze_source_record_signals(trimmed, title, excerpt);
    !(signals.low_priority_hits > 0 || signals.low_priority_dominates())
}

pub(crate) fn local_business_discovery_source_allowed_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    local_business_discovery_source_allowed_with_contract_and_projection(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

pub(crate) fn retrieval_affordances_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> Vec<RetrievalAffordanceKind> {
    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    let mut affordances = Vec::new();
    if projection_candidate_url_allowed_with_contract_and_projection(
        retrieval_contract,
        query_contract,
        &projection,
        raw,
        title,
        excerpt,
    ) {
        affordances.push(RetrievalAffordanceKind::DirectCitationRead);
    }
    if retrieval_contract_entity_diversity_required(retrieval_contract, query_contract)
        && local_business_discovery_source_allowed_with_contract_and_projection(
            retrieval_contract,
            query_contract,
            &projection,
            raw,
            title,
            excerpt,
        )
    {
        affordances.push(RetrievalAffordanceKind::DiscoveryExpansionSeedRead);
    }
    affordances
}

pub(crate) fn retrieval_affordances_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> Vec<RetrievalAffordanceKind> {
    retrieval_affordances_with_contract_and_locality_hint(
        None,
        query_contract,
        min_sources,
        source_hints,
        locality_hint,
        raw,
        title,
        excerpt,
    )
}

pub(crate) fn preferred_pre_read_action_count_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> usize {
    let required = min_sources.max(1) as usize;
    let mut direct_reads = 0usize;
    let mut discovery_seed_reads = 0usize;

    for hint in source_hints {
        let affordances = retrieval_affordances_with_contract_and_locality_hint(
            retrieval_contract,
            query_contract,
            min_sources,
            source_hints,
            locality_hint,
            &hint.url,
            hint.title.as_deref().unwrap_or_default(),
            &hint.excerpt,
        );
        if affordances.contains(&RetrievalAffordanceKind::DirectCitationRead) {
            direct_reads = direct_reads.saturating_add(1);
        }
        if affordances.contains(&RetrievalAffordanceKind::DiscoveryExpansionSeedRead) {
            discovery_seed_reads = discovery_seed_reads.saturating_add(1);
        }
    }

    if direct_reads >= required {
        required
    } else if discovery_seed_reads > 0
        && retrieval_contract_entity_diversity_required(retrieval_contract, query_contract)
    {
        1
    } else {
        required
    }
}

pub(crate) fn preferred_pre_read_action_count_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> usize {
    preferred_pre_read_action_count_with_contract_and_locality_hint(
        None,
        query_contract,
        min_sources,
        source_hints,
        locality_hint,
    )
}

pub(crate) fn projection_candidate_listing_disallowed_with_contract_and_projection(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    is_multi_item_listing_url(raw)
        && !local_business_detail_root_candidate_allowed_with_contract(
            retrieval_contract,
            query_contract,
            projection,
            raw,
            title,
            excerpt,
        )
}

pub(crate) fn projection_candidate_listing_disallowed_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    raw: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    projection_candidate_listing_disallowed_with_contract_and_projection(
        None,
        query_contract,
        projection,
        raw,
        title,
        excerpt,
    )
}

pub(crate) fn resolved_hint_candidate_url(hint: &PendingSearchReadSummary) -> Option<String> {
    let trimmed = hint.url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if projection_candidate_url_allowed(trimmed) {
        return Some(trimmed.to_string());
    }
    let candidate = source_url_from_metadata_excerpt(&hint.excerpt)?;
    projection_candidate_url_allowed(&candidate).then_some(candidate)
}

fn resolved_hint_candidate_url_with_projection(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    hint: &PendingSearchReadSummary,
) -> Option<String> {
    let trimmed = hint.url.trim();
    let title = hint.title.as_deref().unwrap_or_default();
    let excerpt = hint.excerpt.as_str();
    if projection_candidate_url_allowed_with_projection(
        query_contract,
        projection,
        trimmed,
        title,
        excerpt,
    ) {
        return Some(trimmed.to_string());
    }
    let candidate = source_url_from_metadata_excerpt(excerpt)?;
    projection_candidate_url_allowed_with_projection(
        query_contract,
        projection,
        &candidate,
        title,
        excerpt,
    )
    .then_some(candidate)
}

fn resolved_hint_candidate_url_with_contract_and_affordance(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    projection: &QueryConstraintProjection,
    hint: &PendingSearchReadSummary,
) -> Option<String> {
    let trimmed = hint.url.trim();
    let title = hint.title.as_deref().unwrap_or_default();
    let excerpt = hint.excerpt.as_str();
    let affordances = retrieval_affordances_with_contract_and_locality_hint(
        retrieval_contract,
        query_contract,
        1,
        std::slice::from_ref(hint),
        projection.locality_scope.as_deref(),
        trimmed,
        title,
        excerpt,
    );
    if !affordances.is_empty() {
        return Some(trimmed.to_string());
    }

    let candidate = source_url_from_metadata_excerpt(excerpt)?;
    let affordances = retrieval_affordances_with_contract_and_locality_hint(
        retrieval_contract,
        query_contract,
        1,
        std::slice::from_ref(hint),
        projection.locality_scope.as_deref(),
        &candidate,
        title,
        excerpt,
    );
    (!affordances.is_empty()).then_some(candidate)
}

fn resolved_hint_candidate_url_with_affordance(
    query_contract: &str,
    projection: &QueryConstraintProjection,
    hint: &PendingSearchReadSummary,
) -> Option<String> {
    resolved_hint_candidate_url_with_contract_and_affordance(None, query_contract, projection, hint)
}

pub(crate) fn collect_projection_candidate_urls_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    target_count: usize,
    distinct_domain_floor: usize,
    blocked_domains: &BTreeSet<String>,
    locality_hint: Option<&str>,
) -> Vec<String> {
    #[derive(Clone)]
    struct CandidateRecord {
        url: String,
        title: String,
        excerpt: String,
        compatibility: CandidateConstraintCompatibility,
        affordances: Vec<RetrievalAffordanceKind>,
        low_priority: bool,
        headline_low_quality: bool,
        headline_actionable: bool,
        source_relevance_score: usize,
        original_idx: usize,
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    let headline_lookup_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, query_contract);
    let mut ordered_candidates = Vec::<CandidateRecord>::new();
    let mut seen_urls = BTreeSet::new();
    let mut push_candidate = |candidate_url: &str, title: &str, excerpt: &str| {
        let trimmed = candidate_url.trim();
        let affordances = retrieval_affordances_with_contract_and_locality_hint(
            retrieval_contract,
            query_contract,
            min_sources.max(1),
            source_hints,
            locality_hint,
            trimmed,
            title,
            excerpt,
        );
        if affordances.is_empty() {
            return;
        }
        if source_has_human_challenge_signal(trimmed, title, excerpt) {
            return;
        }
        if canonical_domain_key(trimmed)
            .map(|domain| blocked_domains.contains(&domain))
            .unwrap_or(false)
        {
            return;
        }
        let dedup_key = trimmed.to_ascii_lowercase();
        if !seen_urls.insert(dedup_key) {
            return;
        }

        let compatibility = candidate_constraint_compatibility(
            &projection.constraints,
            &projection.query_facets,
            &projection.query_native_tokens,
            &projection.query_tokens,
            &projection.locality_tokens,
            projection.locality_scope.is_some(),
            trimmed,
            title,
            excerpt,
        );
        let signals = analyze_source_record_signals(trimmed, title, excerpt);
        let headline_source = PendingSearchReadSummary {
            url: trimmed.to_string(),
            title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
            excerpt: excerpt.trim().to_string(),
        };
        let headline_low_quality =
            headline_lookup_mode && headline_source_is_low_quality(trimmed, title, excerpt);
        let headline_actionable =
            headline_lookup_mode && headline_source_is_actionable(&headline_source);
        ordered_candidates.push(CandidateRecord {
            url: trimmed.to_string(),
            title: title.trim().to_string(),
            excerpt: excerpt.trim().to_string(),
            compatibility,
            affordances,
            low_priority: source_has_human_challenge_signal(trimmed, title, excerpt)
                || signals.low_priority_hits > 0
                || signals.low_priority_dominates(),
            headline_low_quality,
            headline_actionable,
            source_relevance_score: signals.relevance_score(false),
            original_idx: ordered_candidates.len(),
        });
    };

    for selected in selected_urls {
        let selected_trimmed = selected.trim();
        if selected_trimmed.is_empty() {
            continue;
        }
        let matched_hint = source_hints.iter().find(|hint| {
            let hint_url = hint.url.trim();
            hint_url.eq_ignore_ascii_case(selected_trimmed)
                || url_structurally_equivalent(hint_url, selected_trimmed)
                || resolved_hint_candidate_url_with_contract_and_affordance(
                    retrieval_contract,
                    query_contract,
                    &projection,
                    hint,
                )
                .map(|resolved| {
                    resolved.eq_ignore_ascii_case(selected_trimmed)
                        || url_structurally_equivalent(&resolved, selected_trimmed)
                })
                .unwrap_or(false)
        });
        let title = matched_hint
            .and_then(|hint| hint.title.as_deref())
            .unwrap_or_default();
        let excerpt = matched_hint
            .map(|hint| hint.excerpt.as_str())
            .unwrap_or_default();
        push_candidate(selected_trimmed, title, excerpt);
    }

    for hint in source_hints {
        let Some(candidate) = resolved_hint_candidate_url_with_contract_and_affordance(
            retrieval_contract,
            query_contract,
            &projection,
            hint,
        ) else {
            continue;
        };
        push_candidate(
            &candidate,
            hint.title.as_deref().unwrap_or_default(),
            &hint.excerpt,
        );
    }

    if headline_lookup_mode {
        ordered_candidates.sort_by(|left, right| {
            let right_direct = right
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead);
            let left_direct = left
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead);
            let right_passes = compatibility_passes_projection(&projection, &right.compatibility);
            let left_passes = compatibility_passes_projection(&projection, &left.compatibility);
            right
                .headline_actionable
                .cmp(&left.headline_actionable)
                .then_with(|| left.headline_low_quality.cmp(&right.headline_low_quality))
                .then_with(|| right_direct.cmp(&left_direct))
                .then_with(|| right_passes.cmp(&left_passes))
                .then_with(|| {
                    right
                        .compatibility
                        .compatibility_score
                        .cmp(&left.compatibility.compatibility_score)
                })
                .then_with(|| {
                    right
                        .source_relevance_score
                        .cmp(&left.source_relevance_score)
                })
                .then_with(|| right.affordances.len().cmp(&left.affordances.len()))
                .then_with(|| left.original_idx.cmp(&right.original_idx))
                .then_with(|| left.url.cmp(&right.url))
        });
    }

    let required_floor = distinct_domain_floor.max(1).min(target_count.max(1));
    let strict_grounded_retrieval = projection.enforce_grounded_compatibility();
    let strict_candidate_count = ordered_candidates
        .iter()
        .filter(|candidate| {
            compatibility_passes_projection(&projection, &candidate.compatibility)
                && !candidate.low_priority
        })
        .count();
    let headline_non_low_quality_count = ordered_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
                && !candidate.headline_low_quality
        })
        .count();
    let headline_actionable_count = ordered_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
                && candidate.headline_actionable
                && !candidate.headline_low_quality
        })
        .count();
    let headline_direct_candidate_count = ordered_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
        })
        .count();
    let compatible_candidate_count = ordered_candidates
        .iter()
        .filter(|candidate| compatibility_passes_projection(&projection, &candidate.compatibility))
        .count();

    let filtered_candidates = if headline_lookup_mode && headline_actionable_count >= required_floor
    {
        ordered_candidates
            .into_iter()
            .filter(|candidate| {
                candidate
                    .affordances
                    .contains(&RetrievalAffordanceKind::DirectCitationRead)
                    && candidate.headline_actionable
                    && !candidate.headline_low_quality
            })
            .collect::<Vec<_>>()
    } else if headline_lookup_mode && headline_non_low_quality_count >= required_floor {
        ordered_candidates
            .into_iter()
            .filter(|candidate| {
                candidate
                    .affordances
                    .contains(&RetrievalAffordanceKind::DirectCitationRead)
                    && !candidate.headline_low_quality
            })
            .collect::<Vec<_>>()
    } else if headline_lookup_mode && headline_direct_candidate_count > 0 {
        ordered_candidates
            .into_iter()
            .filter(|candidate| {
                candidate
                    .affordances
                    .contains(&RetrievalAffordanceKind::DirectCitationRead)
            })
            .collect::<Vec<_>>()
    } else if strict_grounded_retrieval && strict_candidate_count > 0 {
        ordered_candidates
            .into_iter()
            .filter(|candidate| {
                compatibility_passes_projection(&projection, &candidate.compatibility)
                    && !candidate.low_priority
            })
            .collect::<Vec<_>>()
    } else if strict_candidate_count >= required_floor {
        ordered_candidates
            .into_iter()
            .filter(|candidate| {
                compatibility_passes_projection(&projection, &candidate.compatibility)
                    && !candidate.low_priority
            })
            .collect::<Vec<_>>()
    } else if compatible_candidate_count > 0 && !strict_grounded_retrieval {
        ordered_candidates
            .into_iter()
            .filter(|candidate| {
                compatibility_passes_projection(&projection, &candidate.compatibility)
            })
            .collect::<Vec<_>>()
    } else {
        ordered_candidates
    };

    let target = target_count.max(1);
    let domain_floor = distinct_domain_floor.min(target);
    let direct_candidate_count = filtered_candidates
        .iter()
        .filter(|candidate| {
            candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
        })
        .count();
    let entity_diversity_direct_only =
        retrieval_contract_entity_diversity_required(retrieval_contract, query_contract)
            && direct_candidate_count > 0;
    let mut output = Vec::new();
    let mut seen_domains = BTreeSet::new();

    if domain_floor > 1 {
        for candidate in &filtered_candidates {
            if output.len() >= target || seen_domains.len() >= domain_floor {
                break;
            }
            if target > 1
                && candidate
                    .affordances
                    .contains(&RetrievalAffordanceKind::DiscoveryExpansionSeedRead)
                && !candidate
                    .affordances
                    .contains(&RetrievalAffordanceKind::DirectCitationRead)
                && (entity_diversity_direct_only || direct_candidate_count >= target)
            {
                continue;
            }
            let domain_key =
                candidate_distinct_domain_key_from_excerpt(&candidate.url, &candidate.excerpt)
                    .unwrap_or_else(|| candidate.url.trim().to_ascii_lowercase());
            if !seen_domains.insert(domain_key) {
                continue;
            }
            output.push(candidate.url.clone());
        }
    }

    for candidate in &filtered_candidates {
        if output.len() >= target {
            break;
        }
        if output.iter().any(|existing| {
            existing.eq_ignore_ascii_case(candidate.url.as_str())
                || url_structurally_equivalent(existing, candidate.url.as_str())
        }) {
            continue;
        }
        if candidate.title.trim().is_empty()
            && candidate.excerpt.trim().is_empty()
            && compatible_candidate_count > 0
        {
            continue;
        }
        if target > 1
            && candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DiscoveryExpansionSeedRead)
            && !candidate
                .affordances
                .contains(&RetrievalAffordanceKind::DirectCitationRead)
            && (entity_diversity_direct_only || direct_candidate_count >= target)
        {
            continue;
        }
        output.push(candidate.url.clone());
    }

    output
}

pub(crate) fn collect_projection_candidate_urls_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    target_count: usize,
    distinct_domain_floor: usize,
    blocked_domains: &BTreeSet<String>,
    locality_hint: Option<&str>,
) -> Vec<String> {
    collect_projection_candidate_urls_with_contract_and_locality_hint(
        None,
        query_contract,
        min_sources,
        selected_urls,
        source_hints,
        target_count,
        distinct_domain_floor,
        blocked_domains,
        locality_hint,
    )
}

pub(crate) fn selected_source_quality_metrics_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> (usize, usize, usize, usize, usize, bool, Vec<String>) {
    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources.max(1),
        source_hints,
        locality_hint,
    );
    let headline_lookup_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, query_contract);
    let mut total_sources = 0usize;
    let mut compatible_sources = 0usize;
    let mut locality_compatible_sources = 0usize;
    let mut low_priority_sources = 0usize;
    let mut distinct_domains = BTreeSet::new();
    let mut low_priority_urls = Vec::new();
    let mut seen_urls = BTreeSet::new();

    for selected in selected_urls {
        let selected_trimmed = selected.trim();
        if selected_trimmed.is_empty() {
            continue;
        }
        let dedup_key = selected_trimmed.to_ascii_lowercase();
        if !seen_urls.insert(dedup_key) {
            continue;
        }

        let (title, excerpt) = source_hints
            .iter()
            .find(|hint| {
                let hint_url = hint.url.trim();
                hint_url.eq_ignore_ascii_case(selected_trimmed)
                    || url_structurally_equivalent(hint_url, selected_trimmed)
            })
            .map(|hint| {
                (
                    hint.title.as_deref().unwrap_or_default(),
                    hint.excerpt.as_str(),
                )
            })
            .unwrap_or(("", ""));
        total_sources = total_sources.saturating_add(1);
        if let Some(domain) = candidate_distinct_domain_key_from_excerpt(selected_trimmed, excerpt)
        {
            distinct_domains.insert(domain);
        }

        if headline_lookup_mode {
            let headline_source = PendingSearchReadSummary {
                url: selected_trimmed.to_string(),
                title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
                excerpt: excerpt.trim().to_string(),
            };
            if headline_source_is_actionable(&headline_source) {
                compatible_sources = compatible_sources.saturating_add(1);
            }
            locality_compatible_sources = locality_compatible_sources.saturating_add(1);
        } else {
            let compatibility = candidate_constraint_compatibility(
                &projection.constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                selected_trimmed,
                title,
                excerpt,
            );
            if compatibility_passes_projection(&projection, &compatibility) {
                compatible_sources = compatible_sources.saturating_add(1);
            }
            if compatibility.locality_compatible {
                locality_compatible_sources = locality_compatible_sources.saturating_add(1);
            }
        }

        let signals = analyze_source_record_signals(selected_trimmed, title, excerpt);
        if source_has_human_challenge_signal(selected_trimmed, title, excerpt)
            || signals.low_priority_hits > 0
            || signals.low_priority_dominates()
        {
            low_priority_sources = low_priority_sources.saturating_add(1);
            low_priority_urls.push(selected_trimmed.to_string());
        }
    }

    let required_source_count = min_sources.max(1) as usize;
    let required_domain_floor =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract)
            .min(required_source_count)
            .max(usize::from(required_source_count > 1));
    let locality_floor_met = !projection.locality_scope.is_some()
        || locality_compatible_sources >= required_source_count;
    let distinct_domain_floor_met =
        required_domain_floor == 0 || distinct_domains.len() >= required_domain_floor;
    let quality_floor_met = total_sources >= required_source_count
        && compatible_sources >= required_source_count
        && locality_floor_met
        && distinct_domain_floor_met
        && low_priority_sources == 0;

    (
        total_sources,
        compatible_sources,
        locality_compatible_sources,
        distinct_domains.len(),
        low_priority_sources,
        quality_floor_met,
        low_priority_urls,
    )
}

pub(crate) fn selected_source_quality_metrics_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    selected_urls: &[String],
    source_hints: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> (usize, usize, usize, usize, usize, bool, Vec<String>) {
    selected_source_quality_metrics_with_contract_and_locality_hint(
        None,
        query_contract,
        min_sources,
        selected_urls,
        source_hints,
        locality_hint,
    )
}

pub(crate) fn pre_read_candidate_plan_with_contract(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    candidate_urls: Vec<String>,
    candidate_source_hints: Vec<PendingSearchReadSummary>,
    locality_hint: Option<&str>,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    let total_candidates = candidate_urls.len();
    if total_candidates == 0 {
        let projection = build_query_constraint_projection_with_locality_hint(
            query_contract,
            min_sources,
            &candidate_source_hints,
            locality_hint,
        );
        let requires_constraint_search_probe = projection.has_constraint_objective()
            && (projection
                .constraints
                .scopes
                .contains(&ConstraintScope::TimeSensitive)
                || projection.enforce_grounded_compatibility());
        return PreReadCandidatePlan {
            candidate_urls,
            probe_source_hints: candidate_source_hints.clone(),
            candidate_source_hints,
            total_candidates: 0,
            pruned_candidates: 0,
            resolvable_candidates: 0,
            scoreable_candidates: 0,
            requires_constraint_search_probe,
        };
    }

    let projection = build_query_constraint_projection_with_locality_hint(
        query_contract,
        min_sources,
        &candidate_source_hints,
        locality_hint,
    );
    let headline_lookup_mode =
        retrieval_contract_is_generic_headline_collection(retrieval_contract, query_contract);
    let probe_source_hints = candidate_source_hints.clone();
    let constraints = &projection.constraints;
    let policy = ResolutionPolicy::default();
    let hints_by_url = candidate_source_hints
        .iter()
        .filter_map(|hint| {
            let trimmed = hint.url.trim();
            (!trimmed.is_empty()).then(|| (trimmed.to_string(), hint.clone()))
        })
        .collect::<BTreeMap<_, _>>();

    let mut ranked = candidate_urls
        .iter()
        .enumerate()
        .map(|(idx, url)| {
            let trimmed = url.trim();
            let hint = hints_by_url.get(trimmed);
            let title = hint
                .and_then(|entry| entry.title.as_deref())
                .unwrap_or_default();
            let excerpt = hint.map(|entry| entry.excerpt.as_str()).unwrap_or_default();
            let score = single_snapshot_candidate_envelope_score(
                constraints,
                policy,
                trimmed,
                title,
                excerpt,
            );
            let scoreable = !title.trim().is_empty() || !excerpt.trim().is_empty();
            let compatibility = candidate_constraint_compatibility(
                constraints,
                &projection.query_facets,
                &projection.query_native_tokens,
                &projection.query_tokens,
                &projection.locality_tokens,
                projection.locality_scope.is_some(),
                trimmed,
                title,
                excerpt,
            );
            let resolvable_payload =
                candidate_time_sensitive_resolvable_payload(trimmed, title, excerpt);
            let affordances = retrieval_affordances_with_contract_and_locality_hint(
                retrieval_contract,
                query_contract,
                min_sources,
                &candidate_source_hints,
                locality_hint,
                trimmed,
                title,
                excerpt,
            );
            let listing_disallowed =
                projection_candidate_listing_disallowed_with_contract_and_projection(
                    retrieval_contract,
                    query_contract,
                    &projection,
                    trimmed,
                    title,
                    excerpt,
                );
            let headline_source = PendingSearchReadSummary {
                url: trimmed.to_string(),
                title: (!title.trim().is_empty()).then(|| title.trim().to_string()),
                excerpt: excerpt.trim().to_string(),
            };
            let headline_low_quality =
                headline_lookup_mode && headline_source_is_low_quality(trimmed, title, excerpt);
            let headline_actionable =
                headline_lookup_mode && headline_source_is_actionable(&headline_source);
            (
                idx,
                trimmed.to_string(),
                score,
                scoreable,
                compatibility,
                resolvable_payload,
                affordances,
                listing_disallowed,
                headline_low_quality,
                headline_actionable,
            )
        })
        .collect::<Vec<_>>();
    ranked.sort_by(|left, right| {
        let right_passes =
            !right.6.is_empty() && compatibility_passes_projection(&projection, &right.4);
        let left_passes =
            !left.6.is_empty() && compatibility_passes_projection(&projection, &left.4);
        right
            .9
            .cmp(&left.9)
            .then_with(|| right.8.cmp(&left.8))
            .then_with(|| right.5.cmp(&left.5))
            .then_with(|| right_passes.cmp(&left_passes))
            .then_with(|| right.4.compatibility_score.cmp(&left.4.compatibility_score))
            .then_with(|| right.6.len().cmp(&left.6.len()))
            .then_with(|| compare_candidate_evidence_scores_desc(&left.2, &right.2))
            .then_with(|| right.4.is_compatible.cmp(&left.4.is_compatible))
            .then_with(|| right.3.cmp(&left.3))
            .then_with(|| left.0.cmp(&right.0))
            .then_with(|| left.1.cmp(&right.1))
    });

    let min_required = min_sources.max(1) as usize;
    let resolvable_candidates = ranked
        .iter()
        .filter(|(_, _, score, _, _, _, affordances, _, _, _)| {
            !affordances.is_empty() && envelope_score_resolves_constraint(constraints, score)
        })
        .count();
    let scoreable_candidates = ranked
        .iter()
        .filter(|(_, _, _, scoreable, _, _, affordances, _, _, _)| {
            *scoreable && !affordances.is_empty()
        })
        .count();
    let compatible_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, compatibility, _, affordances, _, _, _)| {
            !affordances.is_empty() && compatibility_passes_projection(&projection, compatibility)
        })
        .count();
    let positive_compatibility_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, compatibility, _, affordances, _, _, _)| {
            !affordances.is_empty()
                && compatibility_passes_projection(&projection, compatibility)
                && compatibility.compatibility_score > 0
        })
        .count();
    let direct_read_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, _, _, affordances, _, _, _)| {
            affordances.contains(&RetrievalAffordanceKind::DirectCitationRead)
        })
        .count();
    let headline_actionable_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, _, _, affordances, _, _, actionable)| {
            !affordances.is_empty() && *actionable
        })
        .count();
    let headline_non_low_quality_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, _, _, affordances, _, low_quality, _)| {
            !affordances.is_empty() && !*low_quality
        })
        .count();
    let locality_compatible_candidates = ranked
        .iter()
        .filter(|(_, _, _, _, compatibility, _, affordances, _, _, _)| {
            !affordances.is_empty() && compatibility.locality_compatible
        })
        .count();
    let can_prune = resolvable_candidates >= min_required && !headline_lookup_mode;
    let enforce_grounded_compatibility = projection.enforce_grounded_compatibility();
    let strict_grounded_compatibility = projection.strict_grounded_compatibility();
    let must_require_compatibility = enforce_grounded_compatibility && !headline_lookup_mode;
    let can_prune_by_compatibility = if strict_grounded_compatibility {
        !(allow_floor_recovery_exploration
            && compatible_candidates > 0
            && compatible_candidates < min_required)
    } else if headline_lookup_mode {
        false
    } else {
        enforce_grounded_compatibility
            && (compatible_candidates >= min_required
                || positive_compatibility_candidates >= min_required)
    };
    let explicit_locality_scope =
        projection.locality_scope.is_some() && !projection.locality_scope_inferred;
    let can_prune_by_locality = projection.locality_scope.is_some()
        && constraints.scopes.contains(&ConstraintScope::TimeSensitive)
        && (locality_compatible_candidates >= min_required
            || (allow_floor_recovery_exploration && locality_compatible_candidates > 0)
            || (explicit_locality_scope && locality_compatible_candidates > 0));
    let can_prune_by_positive_compatibility = !headline_lookup_mode
        && constraints.scopes.contains(&ConstraintScope::TimeSensitive)
        && positive_compatibility_candidates >= min_required;
    let has_constraint_objective = projection.has_constraint_objective();
    let time_sensitive_scope = constraints.scopes.contains(&ConstraintScope::TimeSensitive);
    let reject_search_hub = projection.reject_search_hub_candidates();
    let prefer_direct_reads = direct_read_candidates >= min_required;
    let can_prune_headline_low_quality =
        headline_lookup_mode && headline_non_low_quality_candidates >= min_required;
    let mut requires_constraint_search_probe = if !has_constraint_objective {
        false
    } else {
        let compatibility_gap = compatible_candidates < min_required;
        let resolvability_gap = resolvable_candidates < min_required;
        let grounded_gap = projection.enforce_grounded_compatibility()
            && (scoreable_candidates == 0 || compatibility_gap || direct_read_candidates == 0);
        if strict_grounded_compatibility {
            grounded_gap || resolvability_gap
        } else {
            (constraints.scopes.contains(&ConstraintScope::TimeSensitive)
                && (compatibility_gap || resolvability_gap || scoreable_candidates == 0))
                || grounded_gap
        }
    };

    let mut candidate_urls = ranked
        .iter()
        .filter_map(
            |(_, url, score, _, compatibility, _, affordances, _, low_quality, _)| {
                if reject_search_hub && is_search_hub_url(url) {
                    return None;
                }
                if affordances.is_empty() {
                    return None;
                }
                if can_prune_headline_low_quality && *low_quality {
                    return None;
                }
                if prefer_direct_reads
                    && !affordances.contains(&RetrievalAffordanceKind::DirectCitationRead)
                {
                    return None;
                }
                if can_prune && !envelope_score_resolves_constraint(constraints, score) {
                    return None;
                }
                if must_require_compatibility
                    && !compatibility_passes_projection(&projection, compatibility)
                {
                    return None;
                }
                if can_prune_by_compatibility
                    && !compatibility_passes_projection(&projection, compatibility)
                {
                    return None;
                }
                if (can_prune_by_locality || explicit_locality_scope)
                    && !compatibility.locality_compatible
                {
                    return None;
                }
                if can_prune_by_positive_compatibility && compatibility.compatibility_score == 0 {
                    return None;
                }
                Some(url.to_string())
            },
        )
        .collect::<Vec<_>>();
    if candidate_urls.is_empty() && projection.locality_scope_inferred {
        let fallback_limit = min_required
            .min(INFERRED_SCOPE_FALLBACK_CANDIDATE_COUNT)
            .max(1);
        let positive_fallback = ranked
            .iter()
            .filter(|(_, _, _, _, compatibility, _, affordances, _, _, _)| {
                !affordances.is_empty()
                    && compatibility_passes_projection(&projection, compatibility)
                    && compatibility.compatibility_score > 0
            })
            .filter(|(_, _, _, _, _, _, affordances, _, _, _)| {
                !prefer_direct_reads
                    || affordances.contains(&RetrievalAffordanceKind::DirectCitationRead)
            })
            .take(fallback_limit)
            .map(|(_, url, _, _, _, _, _, _, _, _)| url.to_string())
            .collect::<Vec<_>>();
        candidate_urls = positive_fallback;
    }
    if candidate_urls.len() < min_required && has_constraint_objective && scoreable_candidates > 0 {
        let candidate_count_before_top_up = candidate_urls.len();
        let mut seen_candidate_urls = candidate_urls
            .iter()
            .map(|url| url.trim().to_string())
            .collect::<BTreeSet<_>>();
        for (_, url, _, _, compatibility, resolvable_payload, affordances, _, _, _) in ranked.iter()
        {
            if candidate_urls.len() >= min_required {
                break;
            }
            if seen_candidate_urls.contains(url) || is_search_hub_url(url) {
                continue;
            }
            if affordances.is_empty() {
                continue;
            }
            if prefer_direct_reads
                && !affordances.contains(&RetrievalAffordanceKind::DirectCitationRead)
            {
                continue;
            }
            if !compatibility.locality_compatible {
                continue;
            }
            let compatibility_relevant = if must_require_compatibility {
                compatibility_passes_projection(&projection, compatibility)
            } else {
                compatibility.compatibility_score > 0
                    || compatibility_passes_projection(&projection, compatibility)
                    || (allow_floor_recovery_exploration && compatible_candidates == 0)
            };
            if !compatibility_relevant {
                continue;
            }
            let payload_relevant = if must_require_compatibility && time_sensitive_scope {
                *resolvable_payload
            } else {
                headline_lookup_mode
                    || !time_sensitive_scope
                    || *resolvable_payload
                    || candidate_urls.len() < min_required
                    || (allow_floor_recovery_exploration && compatible_candidates == 0)
            };
            if !payload_relevant {
                continue;
            }
            if seen_candidate_urls.insert(url.to_string()) {
                candidate_urls.push(url.to_string());
            }
        }
        if candidate_urls.len() > candidate_count_before_top_up {
            requires_constraint_search_probe = true;
        }
    }
    let distinct_domain_floor =
        retrieval_contract_required_distinct_domain_floor(retrieval_contract, query_contract);
    if distinct_domain_floor > 1 && !candidate_urls.is_empty() {
        let mut seen_domains = BTreeSet::new();
        let mut distinct_domain_urls = Vec::new();
        for url in &candidate_urls {
            let trimmed = url.trim();
            if trimmed.is_empty() {
                continue;
            }
            let domain_key = hints_by_url
                .get(url)
                .and_then(|hint| {
                    candidate_distinct_domain_key_from_excerpt(trimmed, hint.excerpt.as_str())
                })
                .unwrap_or_else(|| trimmed.to_ascii_lowercase());
            if seen_domains.insert(domain_key) {
                distinct_domain_urls.push(trimmed.to_string());
            }
        }
        if !distinct_domain_urls.is_empty() {
            candidate_urls = distinct_domain_urls;
        }
        if seen_domains.len() < distinct_domain_floor {
            requires_constraint_search_probe = true;
        }
    }
    if candidate_urls.is_empty()
        && has_constraint_objective
        && constraints.scopes.contains(&ConstraintScope::TimeSensitive)
    {
        requires_constraint_search_probe = true;
    }
    if headline_lookup_mode && headline_actionable_candidates < min_required {
        requires_constraint_search_probe = true;
    }
    let kept_urls = candidate_urls.iter().cloned().collect::<BTreeSet<_>>();
    let mut candidate_source_hints = Vec::new();
    let mut seen_hint_urls = BTreeSet::new();
    let mut seen_hint_domains = BTreeSet::new();
    for url in &candidate_urls {
        if let Some(hint) = hints_by_url.get(url) {
            let trimmed = hint.url.trim();
            if !trimmed.is_empty() && seen_hint_urls.insert(trimmed.to_string()) {
                if let Some(domain_key) =
                    candidate_distinct_domain_key_from_excerpt(trimmed, hint.excerpt.as_str())
                {
                    seen_hint_domains.insert(domain_key);
                }
                candidate_source_hints.push(hint.clone());
            }
        }
    }
    // Preserve additional ranked, non-hub compatible hints for citation quality and
    // bounded floor-recovery reads when selected URL inventory is sparse.
    for (_, url, _, _, compatibility, resolvable_payload, affordances, _, low_quality, _) in &ranked
    {
        if seen_hint_urls.contains(url) {
            continue;
        }
        if reject_search_hub && is_search_hub_url(url) {
            continue;
        }
        if affordances.is_empty() {
            continue;
        }
        if can_prune_headline_low_quality && *low_quality {
            continue;
        }
        if prefer_direct_reads
            && !affordances.contains(&RetrievalAffordanceKind::DirectCitationRead)
        {
            continue;
        }
        if must_require_compatibility
            && !compatibility_passes_projection(&projection, compatibility)
        {
            continue;
        }
        if (can_prune_by_locality || explicit_locality_scope) && !compatibility.locality_compatible
        {
            continue;
        }
        let domain_key = hints_by_url
            .get(url)
            .and_then(|hint| candidate_distinct_domain_key_from_excerpt(url, &hint.excerpt))
            .unwrap_or_else(|| url.trim().to_ascii_lowercase());
        let domain_floor_gap = seen_hint_domains.len() < distinct_domain_floor
            && !seen_hint_domains.contains(&domain_key);
        let include_hint = if must_require_compatibility {
            compatibility_passes_projection(&projection, compatibility)
                && (!time_sensitive_scope || *resolvable_payload || domain_floor_gap)
        } else {
            compatibility_passes_projection(&projection, compatibility)
                || compatibility.compatibility_score > 0
                || *resolvable_payload
                || domain_floor_gap
        };
        if !include_hint {
            continue;
        }
        if let Some(hint) = hints_by_url.get(url) {
            let trimmed = hint.url.trim();
            if !trimmed.is_empty() && seen_hint_urls.insert(trimmed.to_string()) {
                if let Some(hint_domain_key) =
                    candidate_distinct_domain_key_from_excerpt(trimmed, hint.excerpt.as_str())
                {
                    seen_hint_domains.insert(hint_domain_key);
                }
                candidate_source_hints.push(hint.clone());
            }
        }
    }

    PreReadCandidatePlan {
        candidate_urls,
        candidate_source_hints,
        probe_source_hints,
        total_candidates,
        pruned_candidates: total_candidates.saturating_sub(kept_urls.len()),
        resolvable_candidates,
        scoreable_candidates,
        requires_constraint_search_probe,
    }
}

pub(crate) fn pre_read_candidate_plan(
    query_contract: &str,
    min_sources: u32,
    candidate_urls: Vec<String>,
    candidate_source_hints: Vec<PendingSearchReadSummary>,
    locality_hint: Option<&str>,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_with_contract(
        None,
        query_contract,
        min_sources,
        candidate_urls,
        candidate_source_hints,
        locality_hint,
        allow_floor_recovery_exploration,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode(
        retrieval_contract,
        query_contract,
        min_sources,
        bundle,
        locality_hint,
        false,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_locality_hint(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint(
        None,
        query_contract,
        min_sources,
        bundle,
        locality_hint,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode(
    retrieval_contract: Option<&WebRetrievalContract>,
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    let (candidate_urls, candidate_source_hints) =
        constrained_candidate_inventory_from_bundle_with_locality_hint(
            query_contract,
            min_sources,
            bundle,
            locality_hint,
        );
    pre_read_candidate_plan_with_contract(
        retrieval_contract,
        query_contract,
        min_sources,
        candidate_urls,
        candidate_source_hints,
        locality_hint,
        allow_floor_recovery_exploration,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_locality_hint_and_recovery_mode(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    locality_hint: Option<&str>,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_contract_and_locality_hint_and_recovery_mode(
        None,
        query_contract,
        min_sources,
        bundle,
        locality_hint,
        allow_floor_recovery_exploration,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_locality_hint_and_recovery_mode(
        query_contract,
        min_sources,
        bundle,
        None,
        false,
    )
}

pub(crate) fn pre_read_candidate_plan_from_bundle_with_recovery_mode(
    query_contract: &str,
    min_sources: u32,
    bundle: &WebEvidenceBundle,
    allow_floor_recovery_exploration: bool,
) -> PreReadCandidatePlan {
    pre_read_candidate_plan_from_bundle_with_locality_hint_and_recovery_mode(
        query_contract,
        min_sources,
        bundle,
        None,
        allow_floor_recovery_exploration,
    )
}
