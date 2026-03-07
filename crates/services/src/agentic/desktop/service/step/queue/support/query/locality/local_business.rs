fn local_business_entity_anchor_tokens(
    candidate: &str,
    locality_hint: Option<&str>,
) -> BTreeSet<String> {
    let scope_tokens = locality_scope_identity_tokens(locality_hint);
    normalized_anchor_tokens(candidate)
        .into_iter()
        .filter(|token| !scope_tokens.contains(token))
        .filter(|token| !GENERIC_LOCAL_BUSINESS_LISTING_TOKENS.contains(&token.as_str()))
        .collect()
}

pub(crate) fn local_business_entity_name_allowed(
    candidate: &str,
    locality_hint: Option<&str>,
) -> bool {
    let Some(normalized) = normalized_local_business_target_name(candidate) else {
        return false;
    };
    let ordered_tokens = normalized
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.trim().is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if ordered_tokens.is_empty() || ordered_tokens.len() > 6 {
        return false;
    }

    let scope_tokens = locality_scope_identity_tokens(locality_hint);
    if ordered_tokens
        .iter()
        .all(|token| scope_tokens.contains(token))
        || ordered_tokens.iter().all(|token| {
            scope_tokens.contains(token)
                || GENERIC_LOCAL_BUSINESS_LISTING_TOKENS.contains(&token.as_str())
        })
    {
        return false;
    }
    if local_business_entity_anchor_tokens(&normalized, locality_hint).is_empty() {
        return false;
    }

    !generic_local_business_listing_candidate(&normalized, ordered_tokens.len())
}

pub(crate) fn local_business_search_entity_label(
    search_query: &str,
    locality_hint: Option<&str>,
) -> Option<String> {
    let scope_tokens = scope_tokens_for_local_business_anchor(search_query, locality_hint);
    let structural_tokens = query_structural_directive_tokens(search_query);
    let mut best: Option<String> = None;

    for phrase in quoted_query_phrases(search_query) {
        let normalized_phrase = normalized_local_business_target_name(&phrase)
            .unwrap_or_else(|| compact_whitespace(&phrase));
        let tokens =
            ordered_anchor_phrase_tokens(&normalized_phrase, &scope_tokens, &structural_tokens);
        if tokens.is_empty() || tokens.iter().all(|token| scope_tokens.contains(token)) {
            continue;
        }
        if tokens.len() >= 2 {
            return Some(normalized_phrase);
        }
        if best.is_none() {
            best = Some(normalized_phrase);
        }
    }

    best
}

pub(crate) fn local_business_search_entity_anchor_tokens(
    search_query: &str,
    locality_hint: Option<&str>,
) -> Vec<String> {
    local_business_search_entity_anchor_tokens_with_contract(search_query, None, locality_hint)
}

pub(crate) fn local_business_search_entity_anchor_tokens_with_contract(
    search_query: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    locality_hint: Option<&str>,
) -> Vec<String> {
    let resolved = resolved_query_contract_with_locality_hint(search_query, locality_hint);
    if resolved.trim().is_empty() {
        return Vec::new();
    }

    let local_business_lookup = retrieval_contract
        .map(|contract| {
            (crate::agentic::web::contract_requires_geo_scoped_entity_expansion(contract)
                && contract.comparison_required
                && contract.runtime_locality_required
                && !contract.currentness_required)
                || (contract.runtime_locality_required
                    && !contract.currentness_required
                    && query_native_anchor_tokens(&resolved).len() >= 2)
        })
        .unwrap_or_else(|| {
            let facets = analyze_query_facets(&resolved);
            (facets.locality_sensitive_public_fact
                && facets.grounded_external_required
                && !facets.time_sensitive_public_fact)
                || (effective_locality_scope_hint(locality_hint).is_some()
                    && !facets.time_sensitive_public_fact
                    && query_native_anchor_tokens(&resolved).len() >= 2)
        });
    if !local_business_lookup {
        return Vec::new();
    }

    let scope_tokens = scope_tokens_for_local_business_anchor(&resolved, locality_hint);
    let structural_tokens = query_structural_directive_tokens(search_query);
    local_business_search_entity_label(search_query, locality_hint)
        .map(|label| ordered_anchor_phrase_tokens(&label, &scope_tokens, &structural_tokens))
        .unwrap_or_default()
}

pub(crate) fn source_matches_local_business_search_entity_anchor(
    search_query: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    locality_hint: Option<&str>,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    let anchor_tokens = local_business_search_entity_anchor_tokens_with_contract(
        search_query,
        retrieval_contract,
        locality_hint,
    );
    if anchor_tokens.is_empty() {
        return true;
    }

    let source_tokens = source_anchor_tokens(url, title, excerpt);
    let required_hits = anchor_tokens.len().min(2);
    let direct_hits = anchor_tokens
        .iter()
        .filter(|token| source_tokens.contains(*token))
        .count();
    if direct_hits >= required_hits {
        return true;
    }

    let compact_anchor = anchor_tokens.join("");
    if compact_anchor.len() < 6 {
        return false;
    }
    let compact_source = format!("{} {} {}", url, title, excerpt)
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    compact_source.contains(&compact_anchor)
}

pub(crate) fn local_business_target_names_from_attempted_urls(
    attempted_urls: &[String],
    locality_hint: Option<&str>,
) -> Vec<String> {
    let mut targets = Vec::new();
    let mut seen = BTreeSet::new();

    for attempted in attempted_urls {
        let Some(query) = attempted
            .trim()
            .strip_prefix(LOCAL_BUSINESS_EXPANSION_QUERY_MARKER_PREFIX)
        else {
            continue;
        };
        let Some(target_name) = local_business_search_entity_label(query, locality_hint) else {
            continue;
        };
        let dedup_key = target_name.to_ascii_lowercase();
        if !seen.insert(dedup_key) {
            continue;
        }
        targets.push(target_name);
    }

    targets
}

fn generic_local_business_listing_candidate(candidate: &str, token_count: usize) -> bool {
    if token_count == 0 {
        return false;
    }

    let normalized = compact_whitespace(candidate).to_ascii_lowercase();
    let listing_hits = normalized_anchor_tokens(&normalized)
        .iter()
        .filter(|token| GENERIC_LOCAL_BUSINESS_LISTING_TOKENS.contains(&token.as_str()))
        .count();
    let strong_listing_phrase = normalized.starts_with("where to eat ")
        || normalized.starts_with("best ")
        || normalized.starts_with("top ")
        || normalized.contains(" guide")
        || normalized.contains(" directory")
        || normalized.contains(" listing")
        || normalized.contains(" reviews");

    strong_listing_phrase || (token_count >= 2 && listing_hits >= 2)
}

pub(crate) fn local_business_collection_surface_candidate(
    locality_hint: Option<&str>,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if is_search_hub_url(url) || is_multi_item_listing_url(url) {
        return false;
    }
    if !local_business_scope_matches_source(locality_hint, url, title, excerpt) {
        return false;
    }
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    let Some(last_segment) = parsed.path_segments().and_then(|segments| {
        segments
            .filter(|segment| !segment.trim().is_empty())
            .next_back()
            .map(str::to_string)
    }) else {
        return false;
    };
    let slug_structurally_looks_like_collection =
        !last_segment.ends_with('-') && !last_segment.chars().any(|ch| ch.is_ascii_digit());
    if !slug_structurally_looks_like_collection {
        return false;
    }

    let combined = compact_whitespace(format!("{} {}", title, excerpt).trim());
    let combined_tokens = normalized_anchor_tokens(&combined);
    if combined_tokens.len() <= 3
        || !generic_local_business_listing_candidate(&combined, combined_tokens.len())
    {
        return false;
    }

    let category_candidate = local_business_target_candidate_from_title(title, locality_hint)
        .or_else(|| local_business_target_candidate_from_url(url, locality_hint));
    let Some(category_candidate) = category_candidate else {
        return false;
    };
    let category_tokens = normalized_anchor_tokens(&category_candidate);
    if category_tokens.is_empty() || category_tokens.len() > 2 {
        return false;
    }

    let source_tokens = source_anchor_tokens(url, title, excerpt);
    let required_hits = category_tokens.len().min(2).max(1);
    category_tokens
        .iter()
        .filter(|token| source_tokens.contains(*token))
        .count()
        >= required_hits
}

fn is_local_business_structural_id_token(token: &str) -> bool {
    let lower = token.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    if lower.chars().all(|ch| ch.is_ascii_digit()) {
        return true;
    }

    let mut chars = lower.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_alphabetic() && chars.clone().count() > 0 && chars.all(|ch| ch.is_ascii_digit())
}

fn local_business_target_candidate_from_title(
    title: &str,
    locality_hint: Option<&str>,
) -> Option<String> {
    let trimmed = compact_whitespace(title);
    if trimmed.trim().is_empty() || is_low_signal_title(&trimmed) {
        return None;
    }

    let mut candidate = trimmed.as_str();
    for separator in [" | ", " - ", " — ", " – ", ": "] {
        if let Some((left, _)) = candidate.split_once(separator) {
            candidate = left.trim();
            break;
        }
    }
    if let Some((left, _)) = candidate.split_once(',') {
        candidate = left.trim();
    }

    let normalized = normalized_local_business_target_name(candidate)?;
    let token_count = normalized
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.trim().is_empty())
        .count();
    if token_count == 0 || token_count > 6 {
        return None;
    }

    let scope_tokens = locality_scope_identity_tokens(locality_hint);
    let candidate_tokens = local_business_entity_anchor_tokens(&normalized, locality_hint);
    if candidate_tokens.is_empty()
        || candidate_tokens
            .iter()
            .all(|token| scope_tokens.contains(token))
        || candidate_tokens.iter().all(|token| {
            scope_tokens.contains(token)
                || GENERIC_LOCAL_BUSINESS_LISTING_TOKENS.contains(&token.as_str())
        })
    {
        return None;
    }
    if generic_local_business_listing_candidate(&normalized, token_count) {
        return None;
    }

    Some(normalized)
}

fn local_business_display_candidate_from_title(
    title: &str,
    locality_hint: Option<&str>,
) -> Option<String> {
    let trimmed = compact_whitespace(title);
    if trimmed.trim().is_empty() || is_low_signal_title(&trimmed) {
        return None;
    }

    let mut candidate = trimmed.as_str();
    for separator in [" | ", " - ", " — ", " – ", ": "] {
        if let Some((left, _)) = candidate.split_once(separator) {
            candidate = left.trim();
            break;
        }
    }
    if let Some((left, _)) = candidate.split_once(',') {
        candidate = left.trim();
    }

    let normalized = normalized_local_business_target_name(candidate)?;
    let ordered_tokens = normalized
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.trim().is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if ordered_tokens.is_empty() || ordered_tokens.len() > 6 {
        return None;
    }

    let scope_tokens = locality_scope_identity_tokens(locality_hint);
    if ordered_tokens
        .iter()
        .all(|token| scope_tokens.contains(token))
        || ordered_tokens.iter().all(|token| {
            scope_tokens.contains(token)
                || GENERIC_LOCAL_BUSINESS_LISTING_TOKENS.contains(&token.as_str())
        })
    {
        return None;
    }

    Some(normalized)
}

fn local_business_target_candidate_from_url(
    url: &str,
    locality_hint: Option<&str>,
) -> Option<String> {
    if is_search_hub_url(url) || is_multi_item_listing_url(url) {
        return None;
    }
    let parsed = Url::parse(url.trim()).ok()?;
    let mut slug = parsed
        .path_segments()
        .and_then(|segments| {
            segments
                .filter(|segment| !segment.trim().is_empty())
                .next_back()
        })?
        .trim()
        .to_string();
    if slug.is_empty() {
        return None;
    }
    if slug.contains("<REDACTED:") || slug.ends_with(".cms") {
        return None;
    }
    slug = slug.trim_end_matches(".html").to_string();

    for marker in [
        "-Reviews-",
        "-reviews-",
        "Reviews-",
        "reviews-",
        "/reviews/",
    ] {
        if let Some((_, suffix)) = slug.rsplit_once(marker) {
            slug = suffix.to_string();
            break;
        }
    }
    slug = slug.replace('_', " ").replace('-', " ");
    let normalized = normalized_local_business_target_name(&slug)?;

    let scope_tokens = locality_scope_identity_tokens(locality_hint);
    let mut tokens = normalized
        .split_whitespace()
        .filter(|token| !token.trim().is_empty())
        .map(|token| token.to_string())
        .collect::<Vec<_>>();
    strip_locality_suffix_tokens(&mut tokens, locality_hint);
    while tokens
        .last()
        .map(|token| scope_tokens.contains(&token.to_ascii_lowercase()))
        .unwrap_or(false)
    {
        tokens.pop();
    }
    while tokens
        .first()
        .map(|token| {
            let lower = token.to_ascii_lowercase();
            lower.chars().all(|ch| ch.is_ascii_digit())
                || ((lower.starts_with('g') || lower.starts_with('d'))
                    && lower[1..].chars().all(|ch| ch.is_ascii_digit()))
        })
        .unwrap_or(false)
    {
        tokens.remove(0);
    }
    tokens.retain(|token| !is_local_business_structural_id_token(token));

    let trimmed = tokens.join(" ");
    let normalized = normalized_local_business_target_name(&trimmed)?;
    let candidate_tokens = local_business_entity_anchor_tokens(&normalized, locality_hint);
    if candidate_tokens.is_empty()
        || candidate_tokens.iter().all(|token| {
            scope_tokens.contains(token)
                || GENERIC_LOCAL_BUSINESS_LISTING_TOKENS.contains(&token.as_str())
        })
    {
        return None;
    }
    let token_count = normalized
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.trim().is_empty())
        .count();
    if token_count == 0 || token_count > 6 {
        return None;
    }
    if generic_local_business_listing_candidate(&normalized, token_count) {
        return None;
    }

    Some(normalized)
}

pub(crate) fn local_business_target_matches_source_host(target_name: &str, url: &str) -> bool {
    let Some(host) = source_host(url) else {
        return false;
    };
    let host_tokens = canonical_source_identity_tokens(&host);
    let target_tokens = canonical_source_identity_tokens(target_name);
    !host_tokens.is_empty() && host_tokens == target_tokens
}

pub(crate) fn local_business_target_name_from_source(
    source: &PendingSearchReadSummary,
    locality_hint: Option<&str>,
) -> Option<String> {
    if is_search_hub_url(&source.url) || is_multi_item_listing_url(&source.url) {
        return None;
    }
    if local_business_collection_surface_candidate(
        locality_hint,
        &source.url,
        source.title.as_deref().unwrap_or_default(),
        &source.excerpt,
    ) {
        return None;
    }
    source
        .title
        .as_deref()
        .and_then(|title| local_business_target_candidate_from_title(title, locality_hint))
        .filter(|candidate| !local_business_target_matches_source_host(candidate, &source.url))
        .or_else(|| local_business_target_candidate_from_url(&source.url, locality_hint))
}

pub(crate) fn local_business_detail_display_name(
    source: &PendingSearchReadSummary,
    locality_hint: Option<&str>,
) -> Option<String> {
    if is_search_hub_url(&source.url) || is_multi_item_listing_url(&source.url) {
        return None;
    }
    if local_business_collection_surface_candidate(
        locality_hint,
        &source.url,
        source.title.as_deref().unwrap_or_default(),
        &source.excerpt,
    ) {
        return None;
    }
    source
        .title
        .as_deref()
        .and_then(|title| local_business_display_candidate_from_title(title, locality_hint))
        .filter(|candidate| !local_business_target_matches_source_host(candidate, &source.url))
        .or_else(|| local_business_target_name_from_source(source, locality_hint))
}

fn local_business_final_detail_source_allowed(
    source: &PendingSearchReadSummary,
    locality_hint: Option<&str>,
) -> bool {
    let url = source.url.trim();
    let title = source.title.as_deref().unwrap_or_default();
    let excerpt = source.excerpt.as_str();
    if url.is_empty()
        || !is_citable_web_url(url)
        || is_search_hub_url(url)
        || is_multi_item_listing_url(url)
    {
        return false;
    }
    if source_has_human_challenge_signal(url, title, excerpt)
        || source_has_terminal_error_signal(url, title, excerpt)
    {
        return false;
    }
    if local_business_collection_surface_candidate(locality_hint, url, title, excerpt) {
        return false;
    }

    local_business_detail_display_name(source, locality_hint)
        .map(|display_name| local_business_entity_name_allowed(&display_name, locality_hint))
        .unwrap_or(false)
}

pub(crate) fn local_business_target_names_from_sources(
    sources: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    limit: usize,
) -> Vec<String> {
    let mut targets = Vec::new();
    let mut seen = BTreeSet::new();

    for source in sources {
        if source_has_human_challenge_signal(
            &source.url,
            source.title.as_deref().unwrap_or_default(),
            &source.excerpt,
        ) || source_has_terminal_error_signal(
            &source.url,
            source.title.as_deref().unwrap_or_default(),
            &source.excerpt,
        ) {
            continue;
        }
        let target_name = local_business_target_name_from_source(source, locality_hint);
        let Some(target_name) = target_name else {
            continue;
        };
        let dedup_key = target_name.to_ascii_lowercase();
        if !seen.insert(dedup_key) {
            continue;
        }
        targets.push(target_name);
        if targets.len() >= limit.max(1) {
            break;
        }
    }

    targets
}

pub(crate) fn merged_local_business_target_names(
    attempted_urls: &[String],
    sources: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    limit: usize,
) -> Vec<String> {
    let limit = limit.max(1);
    let final_detail_sources = sources
        .iter()
        .filter(|source| local_business_final_detail_source_allowed(source, locality_hint))
        .cloned()
        .collect::<Vec<_>>();
    let mut targets = Vec::new();
    let mut seen = BTreeSet::new();

    for target_name in local_business_target_names_from_attempted_urls(attempted_urls, locality_hint)
    {
        let grounded_by_final_detail = final_detail_sources.iter().any(|source| {
            source_matches_local_business_target_name(
                &target_name,
                locality_hint,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            )
        });
        if !grounded_by_final_detail {
            continue;
        }
        if !seen.insert(target_name.to_ascii_lowercase()) {
            continue;
        }
        targets.push(target_name);
        if targets.len() >= limit {
            return targets;
        }
    }

    for target_name in local_business_target_names_from_sources(&final_detail_sources, locality_hint, limit)
    {
        if !seen.insert(target_name.to_ascii_lowercase()) {
            continue;
        }
        targets.push(target_name);
        if targets.len() >= limit {
            break;
        }
    }

    targets
}

fn ordered_local_business_expansion_terms(
    query_contract: &str,
    locality_hint: Option<&str>,
) -> Vec<String> {
    let resolved = resolved_query_contract_with_locality_hint(query_contract, locality_hint);
    if resolved.trim().is_empty() {
        return Vec::new();
    }

    let allowed_tokens = query_semantic_anchor_tokens(&resolved);
    if allowed_tokens.is_empty() {
        return Vec::new();
    }

    let scope_tokens = effective_locality_scope_hint(locality_hint)
        .map(|scope| normalized_locality_tokens(&scope))
        .unwrap_or_default();
    let structural_tokens = query_structural_directive_tokens(&resolved);
    let mut terms = Vec::new();
    let mut seen = BTreeSet::new();
    for raw in resolved.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
            continue;
        }
        if parse_small_count_token(&normalized).is_some() {
            continue;
        }
        if scope_tokens.contains(&normalized)
            || structural_tokens.contains(&normalized)
            || !allowed_tokens.contains(&normalized)
        {
            continue;
        }
        if !seen.insert(normalized.clone()) {
            continue;
        }
        terms.push(normalized);
    }

    terms
}

pub(crate) fn local_business_expansion_query(
    target_name: &str,
    query_contract: &str,
    locality_hint: Option<&str>,
) -> Option<String> {
    let target_name = normalized_local_business_target_name(target_name)?;
    let mut parts = vec![format!("\"{}\"", target_name)];
    let expansion_terms = ordered_local_business_expansion_terms(query_contract, locality_hint);
    if !expansion_terms.is_empty() {
        parts.push(expansion_terms.join(" "));
    }
    if let Some(scope) = effective_locality_scope_hint(locality_hint) {
        parts.push(format!("\"{}\"", scope));
    }
    Some(compact_whitespace(&parts.join(" ")))
}

fn local_business_scope_matches_source(
    locality_hint: Option<&str>,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    let Some(scope) = effective_locality_scope_hint(locality_hint) else {
        return true;
    };
    let scope_tokens = normalized_locality_tokens(&scope);
    if scope_tokens.is_empty() {
        return true;
    }

    let source_tokens = source_locality_tokens(url, title, excerpt);
    let required_hits = scope_tokens.len().min(2).max(1);
    scope_tokens
        .iter()
        .filter(|token| source_tokens.contains(*token))
        .count()
        >= required_hits
}

pub(crate) fn source_matches_local_business_target_name(
    target_name: &str,
    locality_hint: Option<&str>,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    let Some(target_name) = normalized_local_business_target_name(target_name) else {
        return false;
    };
    if !local_business_scope_matches_source(locality_hint, url, title, excerpt) {
        return false;
    }

    let target_tokens = local_business_entity_anchor_tokens(&target_name, locality_hint);
    if target_tokens.is_empty() {
        return false;
    }

    let source_candidate = PendingSearchReadSummary {
        url: url.to_string(),
        title: (!title.trim().is_empty()).then(|| title.to_string()),
        excerpt: excerpt.to_string(),
    };
    if let Some(candidate_name) =
        local_business_target_name_from_source(&source_candidate, locality_hint)
    {
        let candidate_tokens = local_business_entity_anchor_tokens(&candidate_name, locality_hint);
        let required_hits = target_tokens.len().min(2).max(1);
        let candidate_hits = target_tokens
            .iter()
            .filter(|token| candidate_tokens.contains(*token))
            .count();
        if candidate_hits >= required_hits {
            return true;
        }
    }

    let source_tokens = source_anchor_tokens(url, title, excerpt);
    let required_hits = target_tokens.len().min(2).max(1);
    let direct_hits = target_tokens
        .iter()
        .filter(|token| source_tokens.contains(*token))
        .count();
    if direct_hits >= required_hits {
        return true;
    }

    let compact_target = target_name
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    if compact_target.len() < 6 {
        return false;
    }
    let compact_source = format!("{} {} {}", url, title, excerpt)
        .to_ascii_lowercase()
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .collect::<String>();
    compact_source.contains(&compact_target)
}

pub(crate) fn matched_local_business_target_names(
    target_names: &[String],
    sources: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
) -> Vec<String> {
    let mut matched = Vec::new();

    for target_name in target_names {
        if sources.iter().any(|source| {
            source_matches_local_business_target_name(
                target_name,
                locality_hint,
                &source.url,
                source.title.as_deref().unwrap_or_default(),
                &source.excerpt,
            )
        }) {
            matched.push(target_name.clone());
        }
    }

    matched
}

fn local_business_target_source_score(
    query_contract: &str,
    locality_hint: Option<&str>,
    target_name: &str,
    source: &PendingSearchReadSummary,
) -> (usize, usize, usize, usize, usize, usize, usize) {
    let title = source.title.as_deref().unwrap_or_default();
    let excerpt = source.excerpt.as_str();
    let url = source.url.as_str();
    let target_tokens = normalized_anchor_tokens(target_name);
    let locality_tokens = effective_locality_scope_hint(locality_hint)
        .map(|scope| normalized_locality_tokens(&scope))
        .unwrap_or_default();
    let query_tokens = query_native_anchor_tokens(query_contract)
        .into_iter()
        .filter(|token| !target_tokens.contains(token) && !locality_tokens.contains(token))
        .collect::<BTreeSet<_>>();
    let (host_surface, path_surface) = Url::parse(url.trim())
        .ok()
        .map(|parsed| {
            (
                parsed.host_str().unwrap_or_default().to_ascii_lowercase(),
                format!(
                    "{} {}",
                    parsed.path().trim(),
                    parsed.query().unwrap_or_default().trim()
                )
                .to_ascii_lowercase(),
            )
        })
        .unwrap_or_else(|| (url.to_ascii_lowercase(), url.to_ascii_lowercase()));
    let target_host_hits = target_tokens
        .iter()
        .filter(|token| host_surface.contains(token.as_str()))
        .count();
    let target_path_hits = target_tokens
        .iter()
        .filter(|token| path_surface.contains(token.as_str()))
        .count();
    let surface = format!(" {} {} {} ", url, title, excerpt).to_ascii_lowercase();
    let target_surface_hits = target_tokens
        .iter()
        .filter(|token| surface.contains(token.as_str()))
        .count();
    let query_surface_hits = query_tokens
        .iter()
        .filter(|token| surface.contains(token.as_str()))
        .count();
    let signals = analyze_source_record_signals(url, title, excerpt);
    let preferred_quality = usize::from(
        !source_has_human_challenge_signal(url, title, excerpt)
            && !source_has_terminal_error_signal(url, title, excerpt)
            && signals.low_priority_hits == 0
            && !signals.low_priority_dominates(),
    );
    let locality_scope_hits = usize::from(local_business_scope_matches_source(
        locality_hint,
        url,
        title,
        excerpt,
    ));
    let readable_title = usize::from(!is_low_signal_title(title));

    (
        preferred_quality,
        locality_scope_hits,
        target_host_hits,
        query_surface_hits,
        target_path_hits,
        target_surface_hits,
        readable_title,
    )
}

pub(crate) fn selected_local_business_target_sources(
    query_contract: &str,
    target_names: &[String],
    sources: &[PendingSearchReadSummary],
    locality_hint: Option<&str>,
    limit: usize,
) -> Vec<PendingSearchReadSummary> {
    let mut selected = Vec::new();

    for target_name in target_names {
        if selected.len() >= limit {
            break;
        }
        let mut candidates = sources
            .iter()
            .filter(|source| {
                !selected.iter().any(|existing: &PendingSearchReadSummary| {
                    existing.url.eq_ignore_ascii_case(source.url.as_str())
                        || url_structurally_equivalent(existing.url.as_str(), source.url.as_str())
                }) && local_business_final_detail_source_allowed(source, locality_hint)
                    && source_matches_local_business_target_name(
                    target_name,
                    locality_hint,
                    &source.url,
                    source.title.as_deref().unwrap_or_default(),
                    &source.excerpt,
                )
            })
            .collect::<Vec<_>>();
        candidates.sort_by(|left, right| {
            local_business_target_source_score(query_contract, locality_hint, target_name, right)
                .cmp(&local_business_target_source_score(
                    query_contract,
                    locality_hint,
                    target_name,
                    left,
                ))
                .then_with(|| left.url.cmp(&right.url))
        });
        let Some(source) = candidates.into_iter().next() else {
            continue;
        };
        selected.push(source.clone());
    }

    selected
}

pub(crate) fn query_requires_local_business_entity_diversity(query: &str) -> bool {
    let compact = compact_whitespace(query);
    if compact.trim().is_empty() {
        return false;
    }
    let facets = analyze_query_facets(&compact);
    query_prefers_multi_item_cardinality(&compact)
        && query_requests_comparison(&compact)
        && facets.locality_sensitive_public_fact
        && facets.grounded_external_required
        && !facets.time_sensitive_public_fact
}
