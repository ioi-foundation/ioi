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

const LOCAL_BUSINESS_COMPARISON_AXIS_TOKENS: &[&str] = &[
    "address",
    "addresses",
    "hours",
    "menu",
    "menus",
    "phone",
    "phones",
    "price",
    "prices",
    "rating",
    "ratings",
    "reservation",
    "reservations",
    "review",
    "reviews",
];

const LOCAL_BUSINESS_MENU_SURFACE_PATH_SEGMENTS: &[&str] = &["menu", "menus"];
const LOCAL_BUSINESS_MENU_INVENTORY_MARKERS: &[&str] = &[
    "item inventory includes ",
    "customers' favorites include ",
    "customer favorites include ",
    "menu highlights include ",
    "menu items include ",
];
const LOCAL_BUSINESS_POSTAL_ADDRESS_TOKENS: &[&str] = &[
    "ave",
    "avenue",
    "blvd",
    "boulevard",
    "cir",
    "circle",
    "court",
    "ct",
    "drive",
    "dr",
    "hwy",
    "highway",
    "lane",
    "ln",
    "parkway",
    "pkwy",
    "place",
    "pl",
    "rd",
    "road",
    "st",
    "street",
    "suite",
    "ste",
    "trail",
    "trl",
    "way",
];

pub(crate) fn local_business_menu_surface_url(url: &str) -> bool {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    parsed
        .path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.trim().is_empty())
                .any(|segment| {
                    LOCAL_BUSINESS_MENU_SURFACE_PATH_SEGMENTS.contains(
                        &segment.trim().to_ascii_lowercase().as_str(),
                    )
                })
        })
        .unwrap_or(false)
}

pub(crate) fn query_requires_local_business_menu_surface(
    query_contract: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    locality_hint: Option<&str>,
) -> bool {
    let comparison_requested = retrieval_contract
        .map(|contract| contract.comparison_required)
        .unwrap_or_else(|| query_requests_comparison(query_contract));
    let menu_requested = comparison_requested
        && query_native_anchor_tokens(query_contract)
            .iter()
            .any(|token| matches!(token.as_str(), "menu" | "menus"));
    if !menu_requested {
        return false;
    }

    query_requires_local_business_entity_diversity(query_contract)
        || !local_business_search_entity_anchor_tokens_with_contract(
            query_contract,
            retrieval_contract,
            locality_hint,
        )
        .is_empty()
}

pub(crate) fn local_business_menu_inventory_excerpt(
    input: &str,
    max_chars: usize,
) -> Option<String> {
    let compact = compact_whitespace(input);
    if compact.is_empty() {
        return None;
    }

    let sentences = compact
        .split('.')
        .map(compact_whitespace)
        .filter(|value| !value.is_empty())
        .collect::<Vec<_>>();
    let mut excerpt_sentences = sentences
        .iter()
        .find(|sentence| {
            let lower = sentence.to_ascii_lowercase();
            LOCAL_BUSINESS_MENU_INVENTORY_MARKERS
                .iter()
                .any(|marker| lower.starts_with(marker))
        })
        .map(|sentence| vec![sentence.clone()])
        .unwrap_or_default();
    if excerpt_sentences.is_empty() {
        let items = local_business_menu_inventory_items(input, 5);
        if items.len() < 3 {
            return None;
        }
        excerpt_sentences.push(format!("Item inventory includes {}", items.join(", ")));
    }
    if let Some(gallery_sentence) = sentences.iter().find(|sentence| {
        let lower = sentence.to_ascii_lowercase();
        lower.starts_with("related image gallery available with ")
            || lower.starts_with("menu photo gallery available with ")
    }) {
        excerpt_sentences.push(gallery_sentence.clone());
    }

    let excerpt = format!("{}.", excerpt_sentences.join(". "));
    let compact = compact_excerpt(&excerpt, max_chars.max(1));
    (!compact.is_empty()).then_some(compact)
}

pub(crate) fn local_business_menu_inventory_items(input: &str, max_items: usize) -> Vec<String> {
    if max_items == 0 {
        return Vec::new();
    }

    let mut items = Vec::new();
    let mut seen = BTreeSet::new();
    let mut non_item_lines_after_inventory = 0usize;

    for line in input.lines() {
        let Some(item) = normalize_local_business_menu_inventory_item(line) else {
            if !items.is_empty() {
                non_item_lines_after_inventory += 1;
                if non_item_lines_after_inventory >= 2 {
                    break;
                }
            }
            continue;
        };

        non_item_lines_after_inventory = 0;
        let normalized = item.to_ascii_lowercase();
        if seen.insert(normalized) {
            items.push(item);
            if items.len() >= max_items {
                break;
            }
        }
    }

    items
}

fn normalize_local_business_menu_inventory_item(raw: &str) -> Option<String> {
    let compact = compact_whitespace(raw);
    let trimmed = compact
        .trim()
        .trim_matches(|ch: char| matches!(ch, ':' | ';' | '|' | ',' | '-' | '.'))
        .trim();
    if trimmed.is_empty()
        || trimmed.chars().count() < 4
        || trimmed.chars().count() > 96
        || !trimmed.chars().any(|ch| ch.is_ascii_alphabetic())
    {
        return None;
    }

    let lower = trimmed.to_ascii_lowercase();
    if [
        "customers' favorites",
        "customer favorites",
        "menu",
        "menu photo gallery",
        "photo gallery",
        "photo credit",
        "upload menu",
        "upload image",
        "view photo",
        "hours",
        "phone number",
        "address",
        "map",
    ]
    .iter()
    .any(|marker| lower == *marker || lower.contains(marker))
    {
        return None;
    }
    if local_business_postal_address_like(trimmed) {
        return None;
    }

    Some(trimmed.to_string())
}

fn local_business_postal_address_like(candidate: &str) -> bool {
    if let Some((_, rhs)) = candidate.split_once(" - ") {
        if local_business_postal_address_like(rhs) {
            return true;
        }
    }

    let tokens = candidate
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.trim().is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return false;
    }

    let has_numeric_token = tokens.iter().any(|token| {
        token.chars().next().is_some_and(|ch| ch.is_ascii_digit())
    });
    let has_postal_address_token = tokens
        .iter()
        .any(|token| LOCAL_BUSINESS_POSTAL_ADDRESS_TOKENS.contains(&token.as_str()));
    has_numeric_token && has_postal_address_token
}

fn strip_local_business_comparison_axis_tokens(candidate: &str) -> String {
    let mut tokens = compact_whitespace(candidate)
        .split_whitespace()
        .map(|token| token.trim().to_string())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return String::new();
    }

    while tokens
        .first()
        .map(|token| {
            LOCAL_BUSINESS_COMPARISON_AXIS_TOKENS
                .contains(&token.to_ascii_lowercase().as_str())
        })
        .unwrap_or(false)
    {
        tokens.remove(0);
    }
    while tokens
        .first()
        .map(|token| matches!(token.to_ascii_lowercase().as_str(), "for" | "of"))
        .unwrap_or(false)
    {
        tokens.remove(0);
    }
    while tokens
        .last()
        .map(|token| {
            LOCAL_BUSINESS_COMPARISON_AXIS_TOKENS
                .contains(&token.to_ascii_lowercase().as_str())
        })
        .unwrap_or(false)
    {
        tokens.pop();
    }

    compact_whitespace(&tokens.join(" "))
}

fn sanitize_local_business_search_label(
    candidate: &str,
    locality_hint: Option<&str>,
) -> Option<String> {
    let normalized = normalized_local_business_target_name(candidate)
        .unwrap_or_else(|| compact_whitespace(candidate));
    let tokens = normalized
        .split_whitespace()
        .map(str::trim)
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    if tokens.is_empty() {
        return None;
    }

    let cutoff = tokens.iter().position(|token| {
        LOCAL_BUSINESS_COMPARISON_AXIS_TOKENS.contains(&token.to_ascii_lowercase().as_str())
    });
    let truncated = cutoff
        .map(|idx| tokens[..idx].join(" "))
        .unwrap_or_else(|| normalized.clone());
    let compact = compact_whitespace(&truncated);
    local_business_entity_name_allowed(&compact, locality_hint).then_some(compact)
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
        let Some(normalized_phrase) =
            sanitize_local_business_search_label(&phrase, locality_hint)
        else {
            continue;
        };
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
    let structural_tokens = query_structural_directive_tokens(&resolved);
    local_business_search_entity_label(search_query, locality_hint)
        .map(|label| ordered_anchor_phrase_tokens(&label, &scope_tokens, &structural_tokens))
        .filter(|tokens| !tokens.is_empty())
        .unwrap_or_else(|| {
            ordered_anchor_phrase_tokens(&resolved, &scope_tokens, &structural_tokens)
                .into_iter()
                .filter(|token| !GENERIC_LOCAL_BUSINESS_LISTING_TOKENS.contains(&token.as_str()))
                .collect()
        })
}

const LOCAL_BUSINESS_DISCOVERY_CLASS_TOKENS: &[&str] = &[
    "bar",
    "bars",
    "bistro",
    "bistros",
    "cafe",
    "cafes",
    "cuisine",
    "deli",
    "delis",
    "grill",
    "grills",
    "pizzeria",
    "pizzerias",
    "restaurant",
    "restaurants",
    "tavern",
    "taverns",
];

fn local_business_discovery_class_tokens(
    query_contract: &str,
    locality_hint: Option<&str>,
) -> Vec<String> {
    let resolved = resolved_query_contract_with_locality_hint(query_contract, locality_hint);
    if resolved.trim().is_empty() {
        return Vec::new();
    }

    let scope_tokens = locality_scope_identity_tokens(locality_hint);
    let mut tokens = Vec::new();
    let mut seen = BTreeSet::new();
    for raw in resolved.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.is_empty()
            || scope_tokens.contains(&normalized)
            || !LOCAL_BUSINESS_DISCOVERY_CLASS_TOKENS.contains(&normalized.as_str())
            || !seen.insert(normalized.clone())
        {
            continue;
        }
        tokens.push(normalized);
    }

    tokens
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
    let stripped_candidate = strip_local_business_comparison_axis_tokens(candidate);
    let candidate = if stripped_candidate.trim().is_empty() {
        candidate
    } else {
        stripped_candidate.as_str()
    };

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
    let stripped_candidate = strip_local_business_comparison_axis_tokens(candidate);
    let candidate = if stripped_candidate.trim().is_empty() {
        candidate
    } else {
        stripped_candidate.as_str()
    };

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
    let path_segments = parsed
        .path_segments()
        .map(|segments| {
            segments
                .filter(|segment| !segment.trim().is_empty())
                .map(str::trim)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut slug = path_segments.last()?.trim().to_string();
    if slug.is_empty() {
        return None;
    }
    if LOCAL_BUSINESS_MENU_SURFACE_PATH_SEGMENTS.contains(&slug.to_ascii_lowercase().as_str()) {
        if let Some(parent) = path_segments
            .iter()
            .rev()
            .skip(1)
            .find(|segment| !segment.trim().is_empty())
        {
            slug = parent.trim().to_string();
        }
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

pub(crate) fn local_business_discovery_query_contract(
    query_contract: &str,
    locality_hint: Option<&str>,
) -> String {
    let resolved = resolved_query_contract_with_locality_hint(query_contract, locality_hint);
    if resolved.trim().is_empty() {
        return resolved;
    }

    let Some(scope) = effective_locality_scope_hint(locality_hint)
        .or_else(|| explicit_query_scope_hint(&resolved))
    else {
        return resolved;
    };
    let resolved_lower = resolved.to_ascii_lowercase();
    let scope_lower = scope.to_ascii_lowercase();
    let Some(scope_start) = resolved_lower.rfind(&scope_lower) else {
        return resolved;
    };
    let scope_end = scope_start.saturating_add(scope.len());
    let suffix = resolved.get(scope_end..).unwrap_or("").trim();
    if suffix.is_empty() || !query_requests_comparison(suffix) {
        return resolved;
    }

    let trimmed = compact_whitespace(resolved.get(..scope_end).unwrap_or_default())
        .trim()
        .trim_end_matches(|ch: char| matches!(ch, '.' | '!' | '?' | ',' | ';' | ':'))
        .trim()
        .to_string();
    if trimmed.is_empty() {
        resolved
    } else {
        trimmed
    }
}

pub(crate) fn local_business_entity_discovery_query_contract(
    query_contract: &str,
    locality_hint: Option<&str>,
) -> String {
    let discovery_contract = local_business_discovery_query_contract(query_contract, locality_hint);
    if discovery_contract.trim().is_empty() {
        return discovery_contract;
    }

    let resolved = resolved_query_contract_with_locality_hint(&discovery_contract, locality_hint);
    if resolved.trim().is_empty() {
        return resolved;
    }

    let scope = effective_locality_scope_hint(locality_hint)
        .or_else(|| explicit_query_scope_hint(&resolved));
    let scope_tokens = scope
        .as_ref()
        .map(|value| normalized_locality_tokens(value))
        .unwrap_or_default();
    let structural_tokens = query_structural_directive_tokens(&resolved);
    let search_entity_tokens =
        local_business_search_entity_anchor_tokens_with_contract(&resolved, None, locality_hint);
    let mut semantic_tokens = if search_entity_tokens.is_empty() {
        ordered_anchor_phrase_tokens(&resolved, &scope_tokens, &structural_tokens)
            .into_iter()
            .filter(|token| !scope_tokens.contains(token))
            .collect::<Vec<_>>()
    } else {
        search_entity_tokens
    };
    let discovery_class_tokens = local_business_discovery_class_tokens(&resolved, locality_hint);
    if semantic_tokens.len() <= 1 {
        for class_token in discovery_class_tokens {
            if semantic_tokens.iter().any(|token| token == &class_token) {
                continue;
            }
            semantic_tokens.push(class_token);
        }
    }
    if semantic_tokens.is_empty() {
        return discovery_contract;
    }

    let base = semantic_tokens.join(" ");
    match scope {
        Some(scope) => compact_whitespace(&format!("{base} in {scope}")),
        None => compact_whitespace(&base),
    }
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
) -> (usize, usize, usize, usize, usize, usize, usize, usize) {
    let title = source.title.as_deref().unwrap_or_default();
    let excerpt = source.excerpt.as_str();
    let url = source.url.as_str();
    let menu_surface_preferred =
        query_requires_local_business_menu_surface(query_contract, None, locality_hint);
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
    let menu_surface_hits =
        usize::from(!menu_surface_preferred || local_business_menu_surface_url(url));
    let locality_scope_hits = usize::from(local_business_scope_matches_source(
        locality_hint,
        url,
        title,
        excerpt,
    ));
    let readable_title = usize::from(!is_low_signal_title(title));

    (
        preferred_quality,
        menu_surface_hits,
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
    let menu_surface_required =
        query_requires_local_business_menu_surface(query_contract, None, locality_hint);

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
        if menu_surface_required {
            let menu_candidates = candidates
                .iter()
                .filter(|source| local_business_menu_surface_url(source.url.as_str()))
                .cloned()
                .collect::<Vec<_>>();
            if !menu_candidates.is_empty() {
                candidates = menu_candidates;
            }
        }
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

#[cfg(test)]
mod local_business_menu_surface_tests {
    use super::*;

    #[test]
    fn local_business_menu_surface_requirement_falls_back_to_query_contract() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";

        assert!(query_requires_local_business_menu_surface(
            query,
            None,
            Some("Anderson, SC"),
        ));
    }

    #[test]
    fn local_business_menu_inventory_excerpt_prefers_structured_inventory_surface() {
        let excerpt = local_business_menu_inventory_excerpt(
            "Item inventory includes Brothers Special Shrimp Pasta, Chef Salad, Italian Stromboli, Grilled Chicken Salad, and Meat Lovers Calzone. Related image gallery available with 6 images. Brothers Special Shrimp Pasta. Chef Salad.",
            240,
        )
        .expect("inventory excerpt");

        assert!(excerpt.contains("Item inventory includes"));
        assert!(excerpt.contains("Related image gallery available with 6 images."));
        assert!(!excerpt.contains("Chef Salad. Brothers"));
    }

    #[test]
    fn local_business_menu_inventory_excerpt_synthesizes_inventory_from_line_list_surface() {
        let excerpt = local_business_menu_inventory_excerpt(
            "Bread Sticks\n\nHummus\n\nDolmas\n\nOrganic Old Fashioned Chef Salad\n\nOrganic Antipasto Salad\n\nOrganic Chicken Salad\n\nCentral Avenue - 150 E Shockley Ferry Rd\n\nDomino's Pizza - 121 E Shockley Ferry Rd",
            240,
        )
        .expect("inventory excerpt");

        assert!(excerpt.starts_with("Item inventory includes"));
        assert!(excerpt.contains("Bread Sticks"));
        assert!(excerpt.contains("Hummus"));
        assert!(excerpt.contains("Dolmas"));
        assert!(!excerpt.contains("Shockley Ferry Rd"));
        assert!(!excerpt.contains("Domino's Pizza"));
    }
}
