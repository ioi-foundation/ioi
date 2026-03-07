use super::*;

const SCOPE_ANCHOR_MARKERS: &[&str] = &[" in ", " near ", " around ", " at "];
const UNRESOLVED_LOCALITY_SCOPE_PREFIXES: &[&str] = &[
    "me",
    "here",
    "my area",
    "my neighborhood",
    "my neighbourhood",
    "where i am",
    "where im",
    "where i m",
];
const REPLACEABLE_LOCALITY_PLACEHOLDER_PHRASES: &[&str] =
    &["near me", "around me", "around here", "in my area"];
const SCOPE_STRUCTURAL_CONNECTORS: &[&str] = &["and", "with", "for", "to"];
pub(crate) const LOCAL_BUSINESS_EXPANSION_QUERY_MARKER_PREFIX: &str =
    "ioi://local-business-expansion/query/";

pub(crate) fn is_query_stopword(token: &str) -> bool {
    QUERY_COMPATIBILITY_STOPWORDS.contains(&token)
}

fn is_tracking_noise_token(token: &str) -> bool {
    if token.is_empty() {
        return false;
    }
    if token.starts_with("utm") {
        return true;
    }
    if matches!(
        token,
        "msockid" | "fbclid" | "gclid" | "dclid" | "yclid" | "mcid" | "mkt_tok"
    ) {
        return true;
    }
    token.len() >= 16 && token.chars().all(|ch| ch.is_ascii_hexdigit())
}

pub(crate) fn is_locality_scope_noise_token(token: &str) -> bool {
    LOCALITY_SCOPE_NOISE_TOKENS.contains(&token)
}

pub(crate) fn normalized_anchor_tokens(text: &str) -> BTreeSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
                return None;
            }
            if normalized.chars().all(|ch| ch.is_ascii_digit()) {
                return None;
            }
            if is_query_stopword(&normalized) {
                return None;
            }
            if is_tracking_noise_token(&normalized) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

pub(crate) fn normalized_locality_tokens(text: &str) -> BTreeSet<String> {
    let ordered = ordered_normalized_locality_tokens(text);
    let mut tokens = ordered.iter().cloned().collect::<BTreeSet<_>>();
    for window_len in 2..=3usize {
        for window in ordered.windows(window_len) {
            let compact = window.join("");
            if compact.len() >= QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
                tokens.insert(compact);
            }
        }
    }
    tokens
}

pub(crate) fn source_locality_tokens(url: &str, title: &str, excerpt: &str) -> BTreeSet<String> {
    let mut tokens = normalized_locality_tokens(title);
    tokens.extend(normalized_locality_tokens(excerpt));

    if let Ok(parsed) = Url::parse(url.trim()) {
        if let Some(host) = parsed.host_str() {
            tokens.extend(normalized_locality_tokens(host));
        }
        tokens.extend(normalized_locality_tokens(parsed.path()));
        if let Some(query) = parsed.query() {
            tokens.extend(normalized_locality_tokens(query));
        }
    } else {
        tokens.extend(normalized_locality_tokens(url));
    }

    tokens
}

pub(crate) fn ordered_normalized_locality_tokens(text: &str) -> Vec<String> {
    let mut ordered = Vec::new();
    let mut seen = BTreeSet::new();
    for token in text.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        let normalized = token.trim().to_ascii_lowercase();
        if normalized.len() < 2 {
            continue;
        }
        if normalized.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        if is_query_stopword(&normalized) {
            continue;
        }
        if is_tracking_noise_token(&normalized) {
            continue;
        }
        if !seen.insert(normalized.clone()) {
            continue;
        }
        ordered.push(normalized);
    }
    ordered
}

fn quoted_query_phrases(query: &str) -> Vec<String> {
    let mut phrases = Vec::new();
    let mut current = String::new();
    let mut in_quote = false;

    for ch in query.chars() {
        if ch == '"' {
            if in_quote {
                let phrase = compact_whitespace(&current);
                if !phrase.trim().is_empty() {
                    phrases.push(phrase);
                }
                current.clear();
            }
            in_quote = !in_quote;
            continue;
        }
        if in_quote {
            current.push(ch);
        }
    }

    phrases
}

pub(crate) fn ordered_anchor_phrase_tokens(
    phrase: &str,
    scope_tokens: &BTreeSet<String>,
    structural_tokens: &BTreeSet<String>,
) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut seen = BTreeSet::new();

    for raw in phrase.split(|ch: char| !ch.is_ascii_alphanumeric()) {
        let normalized = raw.trim().to_ascii_lowercase();
        if normalized.len() < QUERY_COMPATIBILITY_MIN_TOKEN_CHARS {
            continue;
        }
        if normalized.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        if is_query_stopword(&normalized)
            || is_tracking_noise_token(&normalized)
            || scope_tokens.contains(&normalized)
            || structural_tokens.contains(&normalized)
        {
            continue;
        }
        if !seen.insert(normalized.clone()) {
            continue;
        }
        tokens.push(normalized);
    }

    tokens
}

fn scope_tokens_for_local_business_anchor(
    search_query: &str,
    locality_hint: Option<&str>,
) -> BTreeSet<String> {
    let mut scope_tokens = explicit_query_scope_hint(search_query)
        .map(|scope| normalized_locality_tokens(&scope))
        .unwrap_or_default();
    scope_tokens.extend(locality_scope_identity_tokens(locality_hint));
    scope_tokens
}

pub(crate) fn normalized_local_business_target_name(name: &str) -> Option<String> {
    let trimmed = compact_whitespace(name);
    if trimmed.trim().is_empty() {
        return None;
    }

    let mut stripped = String::new();
    let mut parenthetical = String::new();
    let mut depth = 0usize;
    for ch in trimmed.chars() {
        if ch == '(' {
            if depth == 0 {
                parenthetical.clear();
            } else {
                parenthetical.push(ch);
            }
            depth = depth.saturating_add(1);
            continue;
        }
        if depth > 0 {
            if ch == ')' {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let normalized_inner = parenthetical
                        .chars()
                        .filter(|value| value.is_ascii_alphanumeric())
                        .collect::<String>();
                    let numeric_only = !normalized_inner.is_empty()
                        && normalized_inner.chars().all(|value| value.is_ascii_digit());
                    if !numeric_only {
                        stripped.push(' ');
                        stripped.push_str(parenthetical.trim());
                        stripped.push(' ');
                    }
                    parenthetical.clear();
                    continue;
                }
            }
            parenthetical.push(ch);
            continue;
        }
        stripped.push(ch);
    }
    if depth > 0 && !parenthetical.trim().is_empty() {
        stripped.push(' ');
        stripped.push_str(parenthetical.trim());
    }

    let normalized = stripped
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, ' ' | '&' | '\'' | '-') {
                ch
            } else {
                ' '
            }
        })
        .collect::<String>();
    let compact = compact_whitespace(&normalized);
    (!compact.trim().is_empty()).then_some(compact)
}

fn normalized_us_state_code(raw: &str) -> Option<&'static str> {
    let normalized = raw
        .trim()
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.trim().is_empty())
        .map(|token| token.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    match normalized.as_str() {
        "al" | "alabama" => Some("al"),
        "ak" | "alaska" => Some("ak"),
        "az" | "arizona" => Some("az"),
        "ar" | "arkansas" => Some("ar"),
        "ca" | "california" => Some("ca"),
        "co" | "colorado" => Some("co"),
        "ct" | "connecticut" => Some("ct"),
        "de" | "delaware" => Some("de"),
        "dc" | "district of columbia" => Some("dc"),
        "fl" | "florida" => Some("fl"),
        "ga" | "georgia" => Some("ga"),
        "hi" | "hawaii" => Some("hi"),
        "id" | "idaho" => Some("id"),
        "il" | "illinois" => Some("il"),
        "in" | "indiana" => Some("in"),
        "ia" | "iowa" => Some("ia"),
        "ks" | "kansas" => Some("ks"),
        "ky" | "kentucky" => Some("ky"),
        "la" | "louisiana" => Some("la"),
        "me" | "maine" => Some("me"),
        "md" | "maryland" => Some("md"),
        "ma" | "massachusetts" => Some("ma"),
        "mi" | "michigan" => Some("mi"),
        "mn" | "minnesota" => Some("mn"),
        "ms" | "mississippi" => Some("ms"),
        "mo" | "missouri" => Some("mo"),
        "mt" | "montana" => Some("mt"),
        "ne" | "nebraska" => Some("ne"),
        "nv" | "nevada" => Some("nv"),
        "nh" | "new hampshire" => Some("nh"),
        "nj" | "new jersey" => Some("nj"),
        "nm" | "new mexico" => Some("nm"),
        "ny" | "new york" => Some("ny"),
        "nc" | "north carolina" => Some("nc"),
        "nd" | "north dakota" => Some("nd"),
        "oh" | "ohio" => Some("oh"),
        "ok" | "oklahoma" => Some("ok"),
        "or" | "oregon" => Some("or"),
        "pa" | "pennsylvania" => Some("pa"),
        "ri" | "rhode island" => Some("ri"),
        "sc" | "south carolina" => Some("sc"),
        "sd" | "south dakota" => Some("sd"),
        "tn" | "tennessee" => Some("tn"),
        "tx" | "texas" => Some("tx"),
        "ut" | "utah" => Some("ut"),
        "vt" | "vermont" => Some("vt"),
        "va" | "virginia" => Some("va"),
        "wa" | "washington" => Some("wa"),
        "wv" | "west virginia" => Some("wv"),
        "wi" | "wisconsin" => Some("wi"),
        "wy" | "wyoming" => Some("wy"),
        _ => None,
    }
}

fn us_state_full_name(code: &str) -> Option<&'static str> {
    match code {
        "al" => Some("alabama"),
        "ak" => Some("alaska"),
        "az" => Some("arizona"),
        "ar" => Some("arkansas"),
        "ca" => Some("california"),
        "co" => Some("colorado"),
        "ct" => Some("connecticut"),
        "de" => Some("delaware"),
        "dc" => Some("district of columbia"),
        "fl" => Some("florida"),
        "ga" => Some("georgia"),
        "hi" => Some("hawaii"),
        "id" => Some("idaho"),
        "il" => Some("illinois"),
        "in" => Some("indiana"),
        "ia" => Some("iowa"),
        "ks" => Some("kansas"),
        "ky" => Some("kentucky"),
        "la" => Some("louisiana"),
        "me" => Some("maine"),
        "md" => Some("maryland"),
        "ma" => Some("massachusetts"),
        "mi" => Some("michigan"),
        "mn" => Some("minnesota"),
        "ms" => Some("mississippi"),
        "mo" => Some("missouri"),
        "mt" => Some("montana"),
        "ne" => Some("nebraska"),
        "nv" => Some("nevada"),
        "nh" => Some("new hampshire"),
        "nj" => Some("new jersey"),
        "nm" => Some("new mexico"),
        "ny" => Some("new york"),
        "nc" => Some("north carolina"),
        "nd" => Some("north dakota"),
        "oh" => Some("ohio"),
        "ok" => Some("oklahoma"),
        "or" => Some("oregon"),
        "pa" => Some("pennsylvania"),
        "ri" => Some("rhode island"),
        "sc" => Some("south carolina"),
        "sd" => Some("south dakota"),
        "tn" => Some("tennessee"),
        "tx" => Some("texas"),
        "ut" => Some("utah"),
        "vt" => Some("vermont"),
        "va" => Some("virginia"),
        "wa" => Some("washington"),
        "wv" => Some("west virginia"),
        "wi" => Some("wisconsin"),
        "wy" => Some("wyoming"),
        _ => None,
    }
}

fn locality_scope_identity_tokens(locality_hint: Option<&str>) -> BTreeSet<String> {
    let Some(scope) = effective_locality_scope_hint(locality_hint) else {
        return BTreeSet::new();
    };
    let mut tokens = normalized_locality_tokens(&scope);
    let mut parts = scope.split(',').map(str::trim).filter(|part| !part.is_empty());
    let _city = parts.next();
    if let Some(region) = parts.next() {
        if let Some(code) = normalized_us_state_code(region) {
            tokens.extend(normalized_locality_tokens(code));
            if let Some(full_name) = us_state_full_name(code) {
                tokens.extend(normalized_locality_tokens(full_name));
            }
        }
    }
    tokens
}

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

const SOURCE_HOST_IDENTITY_NOISE_TOKENS: &[&str] = &[
    "www", "ww2", "m", "mobile", "amp", "co", "com", "net", "org", "gov", "edu", "io", "ai", "app",
    "dev", "info", "biz", "me", "us", "uk", "nz", "au", "ca",
];
const LOCALITY_SUFFIX_DESCRIPTOR_TOKENS: &[&str] = &["city", "county", "town", "village"];
const GENERIC_LOCAL_BUSINESS_LISTING_TOKENS: &[&str] = &[
    "article",
    "articles",
    "best",
    "business",
    "city",
    "directory",
    "guide",
    "guides",
    "list",
    "listing",
    "listings",
    "map",
    "most",
    "news",
    "review",
    "reviews",
    "restaurant",
    "restaurants",
    "top",
    "viewed",
];

fn canonical_source_identity_tokens(text: &str) -> BTreeSet<String> {
    text.split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < 2 {
                return None;
            }
            if SOURCE_HOST_IDENTITY_NOISE_TOKENS.contains(&normalized.as_str()) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

fn locality_suffix_variants(locality_hint: Option<&str>) -> Vec<Vec<String>> {
    let Some(scope) = effective_locality_scope_hint(locality_hint) else {
        return Vec::new();
    };
    let ordered = ordered_normalized_locality_tokens(&scope);
    if ordered.is_empty() {
        return Vec::new();
    }

    let long_tokens = ordered
        .iter()
        .filter(|token| token.len() > 2)
        .cloned()
        .collect::<Vec<_>>();
    let short_tokens = ordered
        .iter()
        .filter(|token| token.len() <= 2)
        .cloned()
        .collect::<Vec<_>>();

    let mut variants = Vec::new();
    variants.push(ordered.clone());
    if !long_tokens.is_empty() && long_tokens != ordered {
        variants.push(long_tokens.clone());
    }
    if long_tokens.len() >= 2 {
        for descriptor in LOCALITY_SUFFIX_DESCRIPTOR_TOKENS {
            let mut descriptor_last = long_tokens.clone();
            descriptor_last.push((*descriptor).to_string());
            variants.push(descriptor_last);

            let mut descriptor_first = vec![(*descriptor).to_string()];
            descriptor_first.extend(long_tokens.clone());
            variants.push(descriptor_first);
        }
    }
    variants.extend(short_tokens.into_iter().map(|token| vec![token]));

    let mut deduped = Vec::new();
    let mut seen = BTreeSet::new();
    variants.sort_by(|left, right| right.len().cmp(&left.len()).then_with(|| left.cmp(right)));
    for variant in variants {
        if variant.is_empty() {
            continue;
        }
        let key = variant.join(" ");
        if !seen.insert(key) {
            continue;
        }
        deduped.push(variant);
    }

    deduped
}

fn strip_locality_suffix_tokens(tokens: &mut Vec<String>, locality_hint: Option<&str>) {
    let variants = locality_suffix_variants(locality_hint);
    if variants.is_empty() {
        return;
    }

    loop {
        let mut changed = false;
        for variant in &variants {
            if tokens.len() <= variant.len() {
                continue;
            }
            if tokens_end_with_case_insensitive(tokens, variant) {
                let new_len = tokens.len().saturating_sub(variant.len());
                tokens.truncate(new_len);
                changed = true;
                break;
            }
        }
        if !changed {
            break;
        }
    }
}

fn tokens_end_with_case_insensitive(tokens: &[String], suffix: &[String]) -> bool {
    if tokens.len() < suffix.len() {
        return false;
    }

    tokens[tokens.len() - suffix.len()..]
        .iter()
        .zip(suffix.iter())
        .all(|(left, right)| left.eq_ignore_ascii_case(right))
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

pub(crate) fn source_structural_locality_tokens(url: &str, title: &str) -> Vec<String> {
    let mut tokens = ordered_normalized_locality_tokens(title);
    let mut seen = tokens.iter().cloned().collect::<BTreeSet<_>>();
    if let Ok(parsed) = Url::parse(url.trim()) {
        if !is_locality_scope_inference_hub_url(url) {
            for token in ordered_normalized_locality_tokens(parsed.path()) {
                if seen.insert(token.clone()) {
                    tokens.push(token);
                }
            }
            if let Some(query) = parsed.query() {
                for token in ordered_normalized_locality_tokens(query) {
                    if seen.insert(token.clone()) {
                        tokens.push(token);
                    }
                }
            }
        }
    } else {
        for token in ordered_normalized_locality_tokens(url) {
            if seen.insert(token.clone()) {
                tokens.push(token);
            }
        }
    }
    tokens
}

pub(crate) fn is_locality_scope_inference_hub_url(url: &str) -> bool {
    if is_search_hub_url(url) {
        return true;
    }
    let Ok(parsed) = Url::parse(url.trim()) else {
        return false;
    };
    let Some(host) = parsed.host_str() else {
        return false;
    };
    let host = host.to_ascii_lowercase();
    let path = parsed.path().to_ascii_lowercase();
    host == "news.google.com"
        && (path.starts_with("/rss/articles")
            || path.starts_with("/rss/read")
            || path.starts_with("/rss/topics"))
}

pub(crate) fn sanitize_locality_scope(raw: &str) -> Option<String> {
    let mut out = String::new();
    let mut last_was_space = true;
    for ch in raw.trim().chars() {
        let allowed = ch.is_ascii_alphanumeric() || matches!(ch, ' ' | ',' | '-' | '/');
        if allowed {
            let normalized = if ch.is_ascii_whitespace() { ' ' } else { ch };
            if normalized == ' ' {
                if last_was_space {
                    continue;
                }
                last_was_space = true;
            } else {
                last_was_space = false;
            }
            out.push(normalized);
        } else if !last_was_space {
            out.push(' ');
            last_was_space = true;
        }
        if out.chars().count() >= LOCALITY_SCOPE_MAX_CHARS {
            break;
        }
    }
    let compact = compact_whitespace(&out);
    (!compact.is_empty()).then_some(compact)
}

pub(crate) fn inferred_locality_scope_from_candidate_hints(
    query: &str,
    candidate_hints: &[PendingSearchReadSummary],
) -> Option<String> {
    if candidate_hints.is_empty() {
        return None;
    }

    let query_facets = analyze_query_facets(query);
    let locality_scope_required = query_requires_locality_scope(query, &query_facets);
    if !locality_scope_required {
        return None;
    }
    let semantic_query_tokens = query_semantic_anchor_tokens(query)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let structural_query_tokens = query_structural_directive_tokens(query);
    let mut token_support: BTreeMap<String, usize> = BTreeMap::new();
    let mut structural_token_support: BTreeMap<String, usize> = BTreeMap::new();
    let mut hint_tokens = Vec::new();

    for (rank, hint) in candidate_hints.iter().enumerate() {
        let title = hint.title.as_deref().unwrap_or_default();
        if locality_scope_required
            && !candidate_time_sensitive_resolvable_payload(&hint.url, title, &hint.excerpt)
        {
            continue;
        }
        let locality_hub_hint = is_locality_scope_inference_hub_url(&hint.url);
        let mut tokens = if locality_hub_hint {
            ordered_normalized_locality_tokens(title)
        } else {
            source_structural_locality_tokens(&hint.url, title)
        };
        if tokens.is_empty() {
            tokens = if locality_hub_hint {
                ordered_normalized_locality_tokens(&hint.excerpt)
            } else {
                source_locality_tokens(&hint.url, title, &hint.excerpt)
                    .into_iter()
                    .collect::<Vec<_>>()
            };
        }
        let mut filtered_tokens = Vec::new();
        let mut seen_tokens = BTreeSet::new();
        for token in tokens.into_iter() {
            if token.len() < 2 {
                continue;
            }
            if token.len() > LOCALITY_SCOPE_TOKEN_MAX_CHARS {
                continue;
            }
            if is_query_stopword(&token) {
                continue;
            }
            if is_locality_scope_noise_token(&token) {
                continue;
            }
            if semantic_query_tokens.contains(&token) || structural_query_tokens.contains(&token) {
                continue;
            }
            if analyze_metric_schema(&token).has_metric_payload() {
                continue;
            }
            if !seen_tokens.insert(token.clone()) {
                continue;
            }
            filtered_tokens.push(token);
        }
        if filtered_tokens.is_empty() {
            continue;
        }

        let mut structural_tokens = Vec::new();
        if let Ok(parsed) = Url::parse(hint.url.trim()) {
            structural_tokens.extend(ordered_normalized_locality_tokens(parsed.path()));
            if let Some(query) = parsed.query() {
                structural_tokens.extend(ordered_normalized_locality_tokens(query));
            }
        }
        let mut seen_structural_tokens = BTreeSet::new();
        for token in structural_tokens {
            if token.len() < 2 {
                continue;
            }
            if token.len() > LOCALITY_SCOPE_TOKEN_MAX_CHARS {
                continue;
            }
            if is_query_stopword(&token) || is_locality_scope_noise_token(&token) {
                continue;
            }
            if semantic_query_tokens.contains(&token) || structural_query_tokens.contains(&token) {
                continue;
            }
            if analyze_metric_schema(&token).has_metric_payload() {
                continue;
            }
            if !seen_structural_tokens.insert(token.clone()) {
                continue;
            }
            *structural_token_support.entry(token).or_insert(0) += 1;
        }

        for token in &filtered_tokens {
            *token_support.entry(token.clone()).or_insert(0) += 1;
        }
        hint_tokens.push((rank, filtered_tokens));
    }

    if token_support.is_empty() || hint_tokens.is_empty() {
        return None;
    }

    let mut ranked_hints = hint_tokens
        .into_iter()
        .map(|(rank, tokens)| {
            let consensus_score = tokens
                .iter()
                .map(|token| {
                    token_support
                        .get(token)
                        .copied()
                        .unwrap_or_default()
                        .saturating_sub(1)
                })
                .sum::<usize>();
            let aggregate_support = tokens
                .iter()
                .map(|token| token_support.get(token).copied().unwrap_or_default())
                .sum::<usize>();
            (rank, tokens, consensus_score, aggregate_support)
        })
        .collect::<Vec<_>>();
    ranked_hints.sort_by(
        |(left_rank, _, left_consensus, left_aggregate),
         (right_rank, _, right_consensus, right_aggregate)| {
            right_consensus
                .cmp(left_consensus)
                .then_with(|| left_rank.cmp(right_rank))
                .then_with(|| right_aggregate.cmp(left_aggregate))
        },
    );

    let Some((_, selected_tokens, _, _)) = ranked_hints.first() else {
        return None;
    };
    let has_consensus_tokens = selected_tokens.iter().any(|token| {
        token_support.get(token).copied().unwrap_or_default() >= LOCALITY_INFERENCE_MIN_SUPPORT
    });
    let selection_support_floor = if has_consensus_tokens {
        LOCALITY_INFERENCE_MIN_SUPPORT
    } else {
        1
    };
    let token_order = selected_tokens
        .iter()
        .enumerate()
        .map(|(idx, token)| (token.clone(), idx))
        .collect::<BTreeMap<_, _>>();
    let mut ranked_tokens = selected_tokens
        .iter()
        .filter_map(|token| {
            let support = token_support.get(token).copied().unwrap_or_default();
            (support >= selection_support_floor).then(|| {
                (
                    token.clone(),
                    support,
                    *token_order.get(token).unwrap_or(&usize::MAX),
                )
            })
        })
        .collect::<Vec<_>>();
    if ranked_tokens.is_empty() {
        ranked_tokens = selected_tokens
            .iter()
            .map(|token| {
                (
                    token.clone(),
                    token_support.get(token).copied().unwrap_or_default(),
                    *token_order.get(token).unwrap_or(&usize::MAX),
                )
            })
            .collect::<Vec<_>>();
    }
    ranked_tokens.sort_by(
        |(left_token, left_support, left_order), (right_token, right_support, right_order)| {
            right_support
                .cmp(left_support)
                .then_with(|| left_order.cmp(right_order))
                .then_with(|| left_token.cmp(right_token))
        },
    );

    let scope_tokens = ranked_tokens
        .into_iter()
        .take(LOCALITY_INFERENCE_MAX_TOKENS)
        .map(|(token, _, _)| token)
        .collect::<Vec<_>>();
    if scope_tokens.is_empty() {
        return None;
    }
    let has_structural_locality_anchor = scope_tokens.iter().any(|token| {
        structural_token_support
            .get(token)
            .copied()
            .unwrap_or_default()
            >= selection_support_floor
    });
    if !has_structural_locality_anchor {
        return None;
    }
    sanitize_locality_scope(&scope_tokens.join(" "))
}

pub(crate) fn scope_anchor_start(query_lower: &str) -> Option<usize> {
    scope_anchor_starts(query_lower).next()
}

fn scope_anchor_starts(query_lower: &str) -> impl Iterator<Item = usize> + '_ {
    let mut starts = Vec::new();
    for marker in SCOPE_ANCHOR_MARKERS {
        let mut search_from = 0;
        while let Some(relative_idx) = query_lower[search_from..].find(marker) {
            let start = search_from + relative_idx;
            starts.push(start + marker.len());
            search_from = start + marker.len();
        }
    }
    starts.sort_unstable();
    starts.into_iter()
}

fn starts_with_unresolved_locality_scope(raw_scope: &str) -> bool {
    let normalized = normalized_phrase_query(raw_scope);
    UNRESOLVED_LOCALITY_SCOPE_PREFIXES
        .iter()
        .any(|prefix| normalized.starts_with(&format!(" {prefix} ")))
}

fn truncate_scope_at_structural_boundary(
    raw_scope: &str,
    structural_tokens: &BTreeSet<String>,
) -> String {
    let mut tokens = Vec::new();
    let mut search_from = 0;
    for token in raw_scope.split_whitespace() {
        let Some(relative_idx) = raw_scope[search_from..].find(token) else {
            continue;
        };
        let start = search_from + relative_idx;
        let end = start + token.len();
        search_from = end;
        let normalized = token
            .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
            .to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        tokens.push((start, normalized));
    }

    for (idx, (start, token)) in tokens.iter().enumerate() {
        if idx > 0 && structural_tokens.contains(token) {
            return raw_scope[..*start].trim().to_string();
        }
        if SCOPE_STRUCTURAL_CONNECTORS.contains(&token.as_str())
            && tokens
                .iter()
                .skip(idx + 1)
                .take(3)
                .any(|(_, next)| structural_tokens.contains(next))
        {
            return raw_scope[..*start].trim().to_string();
        }
    }

    raw_scope.trim().to_string()
}

fn explicit_scope_candidate(
    compact: &str,
    start: usize,
    structural_tokens: &BTreeSet<String>,
) -> Option<String> {
    let end = compact[start..]
        .char_indices()
        .find_map(|(idx, ch)| matches!(ch, '?' | '!' | '.').then_some(start + idx))
        .unwrap_or(compact.len());
    let raw_scope = compact[start..end]
        .trim_matches(|ch: char| matches!(ch, '.' | ',' | ';' | ':' | '?' | '!'))
        .trim();
    if raw_scope.is_empty() {
        return None;
    }

    let truncated_scope = truncate_scope_at_structural_boundary(raw_scope, structural_tokens);
    if truncated_scope.is_empty() || starts_with_unresolved_locality_scope(&truncated_scope) {
        return None;
    }

    let mut scope_tokens = truncated_scope.split_whitespace().collect::<Vec<_>>();
    while let Some(last) = scope_tokens.last() {
        let normalized = last
            .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
            .to_ascii_lowercase();
        if normalized.is_empty()
            || is_query_stopword(&normalized)
            || structural_tokens.contains(&normalized)
        {
            scope_tokens.pop();
            continue;
        }
        break;
    }
    if scope_tokens.is_empty() {
        return None;
    }

    let scope = sanitize_locality_scope(&scope_tokens.join(" "))?;
    (!starts_with_unresolved_locality_scope(&scope)).then_some(scope)
}

fn truncate_retrieval_scope_at_goal_semantic_boundary(goal: &str, scope: &str) -> String {
    let goal_compact = compact_whitespace(goal);
    if goal_compact.trim().is_empty() {
        return scope.trim().to_string();
    }

    let goal_scope_tokens = explicit_query_scope_hint(&goal_compact)
        .map(|value| normalized_locality_tokens(&value))
        .unwrap_or_default();
    let goal_structural_tokens = query_structural_directive_tokens(&goal_compact);
    let goal_semantic_tokens = query_native_anchor_tokens(&goal_compact);
    if goal_semantic_tokens.is_empty() && goal_structural_tokens.is_empty() {
        return scope.trim().to_string();
    }

    let mut tokens = Vec::new();
    let mut search_from = 0;
    for token in scope.split_whitespace() {
        let Some(relative_idx) = scope[search_from..].find(token) else {
            continue;
        };
        let start = search_from + relative_idx;
        let end = start + token.len();
        search_from = end;
        let normalized = token
            .trim_matches(|ch: char| !ch.is_ascii_alphanumeric())
            .to_ascii_lowercase();
        if normalized.is_empty() {
            continue;
        }
        tokens.push((start, normalized));
    }

    for (idx, (start, token)) in tokens.iter().enumerate() {
        if idx == 0 {
            continue;
        }
        if !goal_scope_tokens.contains(token)
            && (goal_structural_tokens.contains(token) || goal_semantic_tokens.contains(token))
        {
            return scope[..*start].trim().to_string();
        }
    }

    scope.trim().to_string()
}

fn cleaned_retrieval_scope_for_goal(goal: &str, scope: &str) -> Option<String> {
    let truncated = truncate_retrieval_scope_at_goal_semantic_boundary(goal, scope);
    if truncated.is_empty() {
        return None;
    }

    let scope = sanitize_locality_scope(&truncated)?;
    (!starts_with_unresolved_locality_scope(&scope)).then_some(scope)
}

fn bounded_phrase_span(haystack: &str, phrase: &str) -> Option<(usize, usize)> {
    let bytes = haystack.as_bytes();
    let mut search_from = 0;
    while let Some(relative_idx) = haystack[search_from..].find(phrase) {
        let start = search_from + relative_idx;
        let end = start + phrase.len();
        let boundary_before = start == 0 || !bytes[start - 1].is_ascii_alphanumeric();
        let boundary_after = end == bytes.len() || !bytes[end].is_ascii_alphanumeric();
        if boundary_before && boundary_after {
            return Some((start, end));
        }
        search_from = start + 1;
    }
    None
}

fn replace_locality_placeholder_with_scope(query: &str, scope: &str) -> Option<String> {
    let compact = compact_whitespace(query);
    if compact.is_empty() {
        return None;
    }
    let lower = compact.to_ascii_lowercase();
    let (start, end) = REPLACEABLE_LOCALITY_PLACEHOLDER_PHRASES
        .iter()
        .filter_map(|phrase| bounded_phrase_span(&lower, phrase))
        .min_by_key(|(start, _)| *start)?;

    let prefix = compact[..start].trim();
    let suffix = compact[end..].trim();
    let replaced = match (prefix.is_empty(), suffix.is_empty()) {
        (true, true) => format!("in {scope}"),
        (true, false) => format!("in {scope} {suffix}"),
        (false, true) => format!("{prefix} in {scope}"),
        (false, false) => format!("{prefix} in {scope} {suffix}"),
    };
    Some(compact_whitespace(&replaced))
}

pub(crate) fn explicit_query_scope_hint(query: &str) -> Option<String> {
    let compact = compact_whitespace(query);
    if compact.is_empty() {
        return None;
    }
    let lower = compact.to_ascii_lowercase();
    let structural_tokens = query_structural_directive_tokens(&compact);
    for start in scope_anchor_starts(&lower) {
        if let Some(scope) = explicit_scope_candidate(&compact, start, &structural_tokens) {
            return Some(scope);
        }
    }
    None
}

pub(crate) fn query_requires_locality_scope(query: &str, facets: &QueryFacetProfile) -> bool {
    facets.locality_sensitive_public_fact
        && !facets.workspace_constrained
        && explicit_query_scope_hint(query).is_none()
}

pub(crate) fn query_requires_runtime_locality_scope(query: &str) -> bool {
    let compact = compact_whitespace(query);
    if compact.trim().is_empty() {
        return false;
    }
    let facets = analyze_query_facets(&compact);
    query_requires_locality_scope(&compact, &facets)
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

pub(crate) fn trusted_runtime_locality_scope_from_env() -> Option<String> {
    TRUSTED_LOCALITY_ENV_KEYS.iter().find_map(|key| {
        std::env::var(key)
            .ok()
            .and_then(|raw| sanitize_locality_scope(&raw))
    })
}

pub(crate) fn effective_locality_scope_hint(locality_hint: Option<&str>) -> Option<String> {
    locality_hint
        .and_then(sanitize_locality_scope)
        .or_else(trusted_runtime_locality_scope_from_env)
}

pub(crate) fn append_scope_to_query(query: &str, scope: &str) -> String {
    let trimmed = compact_whitespace(query);
    if trimmed.is_empty() {
        return trimmed;
    }
    let trimmed = trimmed.trim();
    let (base, suffix) = match trimmed
        .chars()
        .last()
        .filter(|ch| matches!(ch, '?' | '!' | '.'))
    {
        Some(punct) => (
            trimmed[..trimmed.len().saturating_sub(1)].trim(),
            punct.to_string(),
        ),
        None => (trimmed, String::new()),
    };
    if base.is_empty() {
        return trimmed.to_string();
    }
    format!("{base} in {scope}{suffix}")
}

pub(crate) fn resolved_query_contract_with_locality_hint(
    query: &str,
    locality_hint: Option<&str>,
) -> String {
    let base = compact_whitespace(query);
    if base.trim().is_empty() {
        return String::new();
    }
    if explicit_query_scope_hint(&base).is_some() {
        return base;
    }
    let facets = analyze_query_facets(&base);
    if !query_requires_locality_scope(&base, &facets) {
        return base;
    }
    let Some(scope) = effective_locality_scope_hint(locality_hint) else {
        return base;
    };
    if let Some(rewritten) = replace_locality_placeholder_with_scope(&base, &scope) {
        return rewritten;
    }
    compact_whitespace(&append_scope_to_query(&base, &scope))
}

pub(crate) fn resolved_query_contract(query: &str) -> String {
    resolved_query_contract_with_locality_hint(query, None)
}

pub(crate) fn semantic_retrieval_query_contract_with_locality_hint(
    query: &str,
    locality_hint: Option<&str>,
) -> String {
    semantic_retrieval_query_contract_with_contract_and_locality_hint(query, None, locality_hint)
}

pub(crate) fn semantic_retrieval_query_contract_with_contract_and_locality_hint(
    query: &str,
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    locality_hint: Option<&str>,
) -> String {
    let resolved = resolved_query_contract_with_locality_hint(query, locality_hint);
    if resolved.trim().is_empty() {
        return resolved;
    }
    if retrieval_contract_is_generic_headline_collection(retrieval_contract, &resolved) {
        return generic_headline_search_phrase(&resolved);
    }

    let facets = analyze_query_facets(&resolved);
    let scope = explicit_query_scope_hint(&resolved);
    if facets.goal.provenance_hits == 0
        && !facets.time_sensitive_public_fact
        && !facets.grounded_external_required
    {
        return resolved;
    }

    let structural_tokens = query_structural_directive_tokens(&resolved);
    let scope_tokens = scope
        .as_ref()
        .map(|scope| normalized_locality_tokens(scope))
        .unwrap_or_default();
    let semantic_tokens =
        ordered_anchor_phrase_tokens(&resolved, &scope_tokens, &structural_tokens)
            .into_iter()
            .filter(|token| token.len() >= QUERY_COMPATIBILITY_MIN_TOKEN_CHARS)
            .filter(|token| !is_query_stopword(token))
            .collect::<Vec<_>>();
    let metric_terms = facets
        .metric_schema
        .axis_hits
        .iter()
        .copied()
        .map(metric_axis_search_phrase)
        .collect::<Vec<_>>();
    let metric_tokens = metric_terms
        .iter()
        .flat_map(|term| normalized_anchor_tokens(term))
        .collect::<BTreeSet<_>>();
    let semantic_subject_tokens = semantic_tokens
        .iter()
        .filter(|token| !metric_tokens.contains(*token))
        .cloned()
        .collect::<Vec<_>>();

    if scope.is_none() && semantic_tokens.len() < 2 {
        if facets.time_sensitive_public_fact && facets.locality_sensitive_public_fact {
            if let Some(token) = semantic_tokens.first() {
                return format!("{token} current conditions temperature humidity wind");
            }
        }
        return resolved;
    }

    if retrieval_contract_prefers_single_fact_snapshot(retrieval_contract, &resolved)
        && !metric_terms.is_empty()
        && !semantic_subject_tokens.is_empty()
    {
        let base = if facets.time_sensitive_public_fact {
            format!(
                "current {} {}",
                semantic_subject_tokens.join(" "),
                metric_terms.join(" ")
            )
        } else {
            format!(
                "{} {}",
                semantic_subject_tokens.join(" "),
                metric_terms.join(" ")
            )
        };
        if let Some(scope) = scope.as_ref() {
            return format!("{base} in {scope}");
        }
        return base;
    }
    let Some(scope) = scope else {
        return semantic_tokens.join(" ");
    };
    let mut semantic_non_scope = semantic_tokens
        .iter()
        .filter(|token| !scope_tokens.contains(*token))
        .cloned()
        .collect::<Vec<_>>();
    if semantic_non_scope.is_empty() {
        if let Some(first) = semantic_tokens.first() {
            semantic_non_scope.push(first.clone());
        } else {
            return resolved;
        }
    }
    format!("{} in {}", semantic_non_scope.join(" "), scope)
}

pub(crate) fn select_web_pipeline_query_contract(goal: &str, retrieval_query: &str) -> String {
    let goal_compact = compact_whitespace(goal);
    let retrieval_compact = compact_whitespace(retrieval_query);
    let goal_trimmed = goal_compact.trim();
    let retrieval_trimmed = retrieval_compact.trim();

    if goal_trimmed.is_empty() {
        return resolved_query_contract(retrieval_trimmed);
    }

    let retrieval_scope = explicit_query_scope_hint(retrieval_trimmed)
        .and_then(|scope| cleaned_retrieval_scope_for_goal(goal_trimmed, &scope));
    let goal_requires_runtime_locality = query_requires_runtime_locality_scope(goal_trimmed);
    let runtime_scope = goal_requires_runtime_locality
        .then(|| effective_locality_scope_hint(None))
        .flatten();
    let mut contract = runtime_scope
        .as_deref()
        .or(retrieval_scope
            .as_deref()
            .filter(|_| goal_requires_runtime_locality))
        .map(|scope| resolved_query_contract_with_locality_hint(goal_trimmed, Some(scope)))
        .unwrap_or_else(|| resolved_query_contract(goal_trimmed));
    if contract.trim().is_empty() {
        contract = goal_trimmed.to_string();
    }

    if retrieval_trimmed.is_empty() {
        return contract;
    }
    if explicit_query_scope_hint(&contract).is_some() {
        return contract;
    }
    if let Some(scope) = retrieval_scope.as_deref() {
        let resolved_with_scope =
            resolved_query_contract_with_locality_hint(&contract, Some(scope));
        if !resolved_with_scope.trim().is_empty() {
            return compact_whitespace(&resolved_with_scope);
        }
    }

    contract
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_titles_are_rejected_as_local_business_targets() {
        let source = PendingSearchReadSummary {
            url: "https://www.restaurantji.com/sc/anderson/vegetarian/".to_string(),
            title: Some("Best Vegetarian Restaurants".to_string()),
            excerpt:
                "THE 10 BEST Italian Restaurants in Anderson, SC with reviews, ratings and menus."
                    .to_string(),
        };

        assert!(local_business_collection_surface_candidate(
            Some("Anderson, SC"),
            &source.url,
            source.title.as_deref().unwrap_or_default(),
            &source.excerpt,
        ));
        assert_eq!(
            local_business_target_name_from_source(&source, Some("Anderson, SC")),
            None
        );
    }

    #[test]
    fn restaurant_titles_remain_valid_local_business_targets() {
        let source = PendingSearchReadSummary {
            url: "https://www.restaurantji.com/sc/anderson/olive-garden-/".to_string(),
            title: Some("Olive Garden Italian Restaurant".to_string()),
            excerpt: "Italian restaurant in Anderson, SC with pasta, soup and breadsticks."
                .to_string(),
        };

        assert!(!local_business_collection_surface_candidate(
            Some("Anderson, SC"),
            &source.url,
            source.title.as_deref().unwrap_or_default(),
            &source.excerpt,
        ));
        assert_eq!(
            local_business_target_name_from_source(&source, Some("Anderson, SC"))
                .as_deref(),
            Some("Olive Garden Italian Restaurant")
        );
    }

    #[test]
    fn locality_listing_identity_is_not_treated_as_business_entity() {
        let source = PendingSearchReadSummary {
            url: "https://www.tripadvisor.com/Restaurants-g30090-c26-Anderson_South_Carolina.html"
                .to_string(),
            title: Some("Restaurants Anderson South Carolina".to_string()),
            excerpt: "Browse Anderson dining results and traveler review rankings.".to_string(),
        };

        assert!(!local_business_entity_name_allowed(
            "Restaurants Anderson South Carolina",
            Some("Anderson, SC")
        ));
        assert_eq!(
            local_business_target_name_from_source(&source, Some("Anderson, SC")),
            None
        );
        assert!(!source_matches_local_business_target_name(
            "Restaurants Anderson South Carolina",
            Some("Anderson, SC"),
            "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/",
            "Brothers Italian Cuisine",
            "Italian restaurant in Anderson, SC with stromboli and manicotti."
        ));
    }

    #[test]
    fn merged_targets_backfill_from_detail_sources_when_attempted_target_only_has_search_hub() {
        let attempted_urls = vec![
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Brothers Italian Cuisine",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Public Well Cafe and Pizza",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
            format!(
                "ioi://local-business-expansion/query/{}",
                local_business_expansion_query(
                    "Olive Garden",
                    "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.",
                    Some("Anderson, SC"),
                )
                .expect("expansion query")
            ),
        ];
        let sources = vec![
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/"
                    .to_string(),
                title: Some("Brothers Italian Cuisine".to_string()),
                excerpt: "Italian restaurant in Anderson, SC with stromboli and manicotti."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/public-well-cafe-and-pizza-/"
                    .to_string(),
                title: Some("Public Well Cafe and Pizza".to_string()),
                excerpt: "Italian restaurant in Anderson, SC with pizza and pasta.".to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.restaurantji.com/sc/anderson/coach-house-restaurant-/"
                    .to_string(),
                title: Some("Coach House Restaurant".to_string()),
                excerpt: "Anderson, SC restaurant with ravioli, lasagna and dinner plates."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.yelp.com/search?cflt=italian&find_loc=Anderson,%20sc"
                    .to_string(),
                title: Some("Best Italian in Anderson, SC".to_string()),
                excerpt: "Olive Garden, Dolce Vita Italian Bistro and Coach House Restaurant."
                    .to_string(),
            },
        ];

        let targets =
            merged_local_business_target_names(&attempted_urls, &sources, Some("Anderson, SC"), 3);

        assert_eq!(
            targets,
            vec![
                "Brothers Italian Cuisine".to_string(),
                "Public Well Cafe and Pizza".to_string(),
                "Coach House Restaurant".to_string(),
            ]
        );
    }
}
