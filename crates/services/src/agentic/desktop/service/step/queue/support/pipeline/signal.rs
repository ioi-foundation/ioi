use super::*;

const DOCUMENT_AUTHORITY_GENERIC_QUERY_TOKENS: &[&str] = &[
    "latest",
    "current",
    "today",
    "briefing",
    "overview",
    "summary",
    "report",
    "reports",
    "news",
    "update",
    "updates",
    "research",
    "write",
    "page",
    "pages",
    "official",
    "public",
    "standard",
    "standards",
    "spec",
    "specs",
    "specification",
    "specifications",
    "guidance",
    "guideline",
    "guidelines",
    "framework",
    "frameworks",
    "policy",
    "policies",
    "program",
    "programs",
    "project",
    "projects",
    "publication",
    "publications",
    "announcement",
    "announcements",
    "release",
    "releases",
    "transition",
    "migration",
    "security",
    "cryptography",
    "encryption",
    "quantum",
    "post",
];

const DOCUMENT_AUTHORITY_SURFACE_MARKERS: &[&str] = &[
    " standard ",
    " standards ",
    " spec ",
    " specs ",
    " specification ",
    " specifications ",
    " guidance ",
    " guideline ",
    " guidelines ",
    " framework ",
    " frameworks ",
    " policy ",
    " policies ",
    " publication ",
    " publications ",
    " announcement ",
    " announcements ",
    " release ",
    " releases ",
    " bulletin ",
    " program ",
    " programs ",
    " project ",
    " projects ",
    " migration ",
    " transition ",
    " faq ",
    " reference ",
    " references ",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CanonicalIdentifierGroup {
    pub(crate) key: &'static str,
    pub(crate) primary_label: &'static str,
    pub(crate) required: bool,
    pub(crate) needles: &'static [&'static str],
}

pub(crate) fn briefing_standard_identifier_groups_for_query(
    _query_contract: &str,
) -> &'static [CanonicalIdentifierGroup] {
    // Subject-specific identifier expansion is intentionally disabled until it can be
    // derived from generic discovery signals rather than query-class heuristics.
    &[]
}

pub(crate) fn briefing_standard_identifier_group_floor(query_contract: &str) -> usize {
    briefing_standard_identifier_groups_for_query(query_contract)
        .iter()
        .filter(|group| group.required)
        .count()
}

fn normalized_identifier_surface(surface: &str) -> String {
    let mut out = String::new();
    let mut prev_space = true;
    for ch in surface.chars() {
        let normalized = if ch.is_ascii_alphanumeric() {
            ch.to_ascii_lowercase()
        } else {
            ' '
        };
        if normalized == ' ' {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
            continue;
        }
        out.push(normalized);
        prev_space = false;
    }
    out.trim().to_string()
}

fn normalized_identifier_needle(needle: &str) -> String {
    normalized_identifier_surface(needle)
}

pub(crate) fn observed_briefing_standard_identifier_groups(
    query_contract: &str,
    surface: &str,
) -> Vec<CanonicalIdentifierGroup> {
    let normalized_surface = normalized_identifier_surface(surface);
    if normalized_surface.is_empty() {
        return Vec::new();
    }
    briefing_standard_identifier_groups_for_query(query_contract)
        .iter()
        .copied()
        .filter(|group| {
            group.needles.iter().any(|needle| {
                let normalized_needle = normalized_identifier_needle(needle);
                !normalized_needle.is_empty() && normalized_surface.contains(&normalized_needle)
            })
        })
        .collect()
}

pub(crate) fn observed_briefing_standard_identifier_labels(
    query_contract: &str,
    surface: &str,
) -> Vec<String> {
    observed_briefing_standard_identifier_groups(query_contract, surface)
        .into_iter()
        .map(|group| group.primary_label.to_string())
        .collect()
}

pub(crate) fn source_briefing_standard_identifier_labels(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> BTreeSet<String> {
    observed_briefing_standard_identifier_labels(
        query_contract,
        &format!("{} {} {}", url, title, excerpt),
    )
    .into_iter()
    .collect()
}

pub(crate) fn source_has_briefing_standard_identifier_signal(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    !source_briefing_standard_identifier_labels(query_contract, url, title, excerpt).is_empty()
}

pub(crate) fn compact_excerpt(input: &str, max_chars: usize) -> String {
    compact_whitespace(input)
        .chars()
        .take(max_chars)
        .collect::<String>()
}

pub(crate) fn looks_like_structured_metadata_noise(input: &str) -> bool {
    let compact = compact_whitespace(input);
    let trimmed = compact.trim();
    if trimmed.is_empty() {
        return false;
    }
    let lower = trimmed.to_ascii_lowercase();
    if [
        "cookie':'",
        "cookie\":\"",
        "set-cookie",
        "cf_clearance",
        "source_url=",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
    {
        return true;
    }
    let script_or_asset_noise = lower.contains("srcset=")
        || lower.contains("[^1]:")
        || (lower.contains("function")
            && (lower.contains("return function")
                || lower.contains("{c()[")
                || lower.contains("}function ")))
        || (lower.contains(" alt=") && lower.contains(" width=") && lower.contains(" height="));
    if script_or_asset_noise {
        return true;
    }
    let marker_hits = [
        "\"@context\"",
        "\"@type\"",
        "datepublished",
        "datemodified",
        "inlanguage",
        "thumbnailurl",
        "contenturl",
        "imageobject",
        "\"width\"",
        "\"height\"",
        "\"caption\"",
    ]
    .iter()
    .filter(|marker| lower.contains(**marker))
    .count();
    if marker_hits == 0 {
        return false;
    }

    let structured_punctuation_hits = lower
        .chars()
        .filter(|ch| matches!(ch, '{' | '}' | '[' | ']' | '"' | ':'))
        .count();
    let strong_structured_shape = lower.contains("\",\"")
        || lower.contains("\":")
        || lower.contains("},{")
        || lower.contains("\"@context\"")
        || lower.contains("\"@type\"");

    marker_hits >= 2 && (structured_punctuation_hits >= 12 || strong_structured_shape)
}

pub(crate) fn prioritized_signal_excerpt(input: &str, max_chars: usize) -> String {
    let compact = compact_whitespace(input);
    if compact.is_empty() {
        return String::new();
    }
    if looks_like_structured_metadata_noise(&compact) {
        return String::new();
    }

    if let Some(metric) = first_metric_sentence(&compact) {
        return metric.chars().take(max_chars).collect();
    }

    if let Some(actionable) = actionable_excerpt(&compact) {
        return actionable.chars().take(max_chars).collect();
    }

    if is_low_signal_excerpt(&compact) {
        return String::new();
    }

    compact.chars().take(max_chars).collect()
}

fn prioritized_standard_identifier_excerpt(
    query_contract: &str,
    input: &str,
    max_chars: usize,
) -> String {
    if briefing_standard_identifier_group_floor(query_contract) == 0 {
        return String::new();
    }
    let compact = compact_whitespace(input);
    if compact.is_empty() || looks_like_structured_metadata_noise(&compact) {
        return String::new();
    }

    #[derive(Clone)]
    struct IdentifierSegment {
        text: String,
        required_labels: BTreeSet<String>,
        total_hits: usize,
        authority_marker_hits: usize,
    }

    let required_labels = briefing_standard_identifier_groups_for_query(query_contract)
        .iter()
        .filter(|group| group.required)
        .map(|group| group.primary_label.to_string())
        .collect::<BTreeSet<_>>();
    let required_floor = required_labels.len();
    let mut segments = compact
        .split(['.', '!', '?', ';', '\n'])
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .filter_map(|segment| {
            let observed_groups =
                observed_briefing_standard_identifier_groups(query_contract, segment);
            if observed_groups.is_empty() {
                return None;
            }
            let candidate = compact_whitespace(segment);
            if candidate.is_empty() {
                return None;
            }
            Some(IdentifierSegment {
                text: candidate,
                required_labels: observed_groups
                    .iter()
                    .filter(|group| group.required)
                    .map(|group| group.primary_label.to_string())
                    .collect(),
                total_hits: observed_groups.len(),
                authority_marker_hits: usize::from(
                    segment
                        .to_ascii_lowercase()
                        .contains("federal information processing standards"),
                ),
            })
        })
        .collect::<Vec<_>>();
    segments.sort_by(|left, right| {
        (
            right.required_labels.len(),
            right.total_hits,
            right.authority_marker_hits,
            usize::MAX.saturating_sub(right.text.len()),
        )
            .cmp(&(
                left.required_labels.len(),
                left.total_hits,
                left.authority_marker_hits,
                usize::MAX.saturating_sub(left.text.len()),
            ))
    });

    let Some(best_segment) = segments.first().cloned() else {
        return String::new();
    };
    let anchored_identifier_excerpt = |segment: &str| {
        let lower = segment.to_ascii_lowercase();
        let anchor = observed_briefing_standard_identifier_groups(query_contract, segment)
            .into_iter()
            .flat_map(|group| group.needles.iter().copied())
            .filter_map(|needle| lower.find(needle))
            .min();
        let Some(anchor) = anchor else {
            return segment.chars().take(max_chars).collect::<String>();
        };
        let start = segment[..anchor]
            .rfind(|ch: char| matches!(ch, '.' | '!' | '?' | ';' | '\n'))
            .map(|idx| idx + 1)
            .or_else(|| {
                segment[..anchor]
                    .rfind(char::is_whitespace)
                    .map(|idx| idx + 1)
            })
            .unwrap_or(0);
        segment[start..].trim().chars().take(max_chars).collect()
    };
    if best_segment.required_labels.len() >= required_floor.max(1) {
        return anchored_identifier_excerpt(&best_segment.text);
    }

    let mut selected_segments = Vec::new();
    let mut covered_required_labels = BTreeSet::new();
    let mut total_len = 0usize;
    for segment in &segments {
        let adds_required_label = segment
            .required_labels
            .iter()
            .any(|label| !covered_required_labels.contains(label));
        if !selected_segments.is_empty() && !adds_required_label {
            continue;
        }
        let projected_len = if selected_segments.is_empty() {
            segment.text.len()
        } else {
            total_len + 2 + segment.text.len()
        };
        if !selected_segments.is_empty() && projected_len > max_chars {
            continue;
        }
        selected_segments.push(segment.text.clone());
        total_len = projected_len;
        covered_required_labels.extend(segment.required_labels.iter().cloned());
        if covered_required_labels.len() >= required_floor.max(1) {
            break;
        }
    }

    if covered_required_labels.len() > best_segment.required_labels.len()
        && !selected_segments.is_empty()
    {
        return anchored_identifier_excerpt(&selected_segments.join(". "));
    }

    anchored_identifier_excerpt(&best_segment.text)
}

pub(crate) fn prioritized_query_grounding_excerpt(
    query_contract: &str,
    min_sources: usize,
    url: &str,
    title: &str,
    input: &str,
    max_chars: usize,
) -> String {
    prioritized_query_grounding_excerpt_with_contract(
        None,
        query_contract,
        min_sources,
        url,
        title,
        input,
        max_chars,
    )
}

pub(crate) fn prioritized_query_grounding_excerpt_with_contract(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query_contract: &str,
    min_sources: usize,
    url: &str,
    title: &str,
    input: &str,
    max_chars: usize,
) -> String {
    let locality_hint = explicit_query_scope_hint(query_contract);
    if local_business_menu_surface_url(url)
        && query_requires_local_business_menu_surface(
            query_contract,
            retrieval_contract,
            locality_hint.as_deref(),
        )
    {
        if let Some(inventory_excerpt) = local_business_menu_inventory_excerpt(input, max_chars) {
            return inventory_excerpt;
        }
    }

    let prioritized_standard_identifier_excerpt =
        prioritized_standard_identifier_excerpt(query_contract, input, max_chars);
    if !prioritized_standard_identifier_excerpt.is_empty()
        && excerpt_has_query_grounding_signal_with_contract(
            retrieval_contract,
            query_contract,
            min_sources,
            url,
            title,
            &prioritized_standard_identifier_excerpt,
        )
    {
        return prioritized_standard_identifier_excerpt;
    }

    let prioritized = prioritized_signal_excerpt(input, max_chars);
    if !prioritized.is_empty()
        && excerpt_has_query_grounding_signal_with_contract(
            retrieval_contract,
            query_contract,
            min_sources,
            url,
            title,
            &prioritized,
        )
    {
        return prioritized;
    }

    let compact = compact_excerpt(input, max_chars);
    if !compact.is_empty()
        && excerpt_has_query_grounding_signal_with_contract(
            retrieval_contract,
            query_contract,
            min_sources,
            url,
            title,
            &compact,
        )
    {
        return compact;
    }

    String::new()
}

pub(crate) fn source_has_human_challenge_signal(url: &str, title: &str, excerpt: &str) -> bool {
    let surface = format!("{} {} {}", url, title, excerpt).to_ascii_lowercase();
    let title_lc = title.trim().to_ascii_lowercase();
    if matches!(
        title_lc.as_str(),
        "vercel security checkpoint" | "security checkpoint"
    ) {
        return true;
    }
    [
        "please enable js",
        "please enable javascript",
        "enable javascript",
        "verify you are human",
        "complete the security check",
        "checking if the site connection is secure",
        "checking your browser before accessing",
        "access denied",
        "captcha",
        "recaptcha",
        "cloudflare",
        "dd={'rt':'c'",
    ]
    .iter()
    .any(|marker| surface.contains(marker))
}

pub(crate) fn source_has_terminal_error_signal(url: &str, title: &str, excerpt: &str) -> bool {
    let surface = format!("{} {} {}", url, title, excerpt).to_ascii_lowercase();
    let title_lc = title.trim().to_ascii_lowercase();
    let excerpt_lc = excerpt.trim().to_ascii_lowercase();
    if matches!(title_lc.as_str(), "429 too many requests" | "403 forbidden")
        || excerpt_lc.starts_with("429 too many requests")
        || excerpt_lc.starts_with("403 forbidden")
    {
        return true;
    }
    [
        "404 not found",
        "page not found",
        "the page you requested could not be found",
        "sorry, the page you were looking for",
        "we can't seem to find the page",
    ]
    .iter()
    .any(|marker| surface.contains(marker))
}

pub(crate) fn source_host(url: &str) -> Option<String> {
    let parsed = Url::parse(url.trim()).ok()?;
    let host = parsed
        .host_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())?;
    Some(host.to_ascii_lowercase())
}

pub(crate) fn source_evidence_signals(source: &PendingSearchReadSummary) -> SourceSignalProfile {
    let title = source.title.as_deref().unwrap_or_default();
    analyze_source_record_signals(&source.url, title, &source.excerpt)
}

pub(crate) fn has_primary_status_authority(signals: SourceSignalProfile) -> bool {
    signals.official_status_host_hits > 0 || signals.primary_status_surface_hits > 0
}

fn document_authority_query_tokens(query_contract: &str) -> BTreeSet<String> {
    query_native_anchor_tokens(query_contract)
        .into_iter()
        .filter(|token| token.len() >= 4)
        .filter(|token| !DOCUMENT_AUTHORITY_GENERIC_QUERY_TOKENS.contains(&token.as_str()))
        .collect()
}

fn document_authority_host_tokens(url: &str) -> BTreeSet<String> {
    source_host(url)
        .into_iter()
        .flat_map(|host| {
            host.split(|ch: char| !ch.is_ascii_alphanumeric())
                .filter_map(|token| {
                    let normalized = token.trim().to_ascii_lowercase();
                    if normalized.len() < 3 {
                        return None;
                    }
                    if matches!(
                        normalized.as_str(),
                        "www" | "com" | "net" | "org" | "gov" | "edu" | "mil" | "int" | "co"
                    ) {
                        return None;
                    }
                    Some(normalized)
                })
                .collect::<Vec<_>>()
        })
        .collect()
}

fn source_has_public_authority_host(url: &str) -> bool {
    let Some(host) = source_host(url) else {
        return false;
    };
    host == "gov"
        || host.ends_with(".gov")
        || host.contains(".gov.")
        || host == "mil"
        || host.ends_with(".mil")
        || host.contains(".mil.")
        || host == "int"
        || host.ends_with(".int")
        || host.contains(".int.")
}

fn source_document_authority_surface_hits(url: &str, title: &str, excerpt: &str) -> usize {
    let surface = format!("{} {} {}", url, title, excerpt)
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>();
    DOCUMENT_AUTHORITY_SURFACE_MARKERS
        .iter()
        .filter(|marker| surface.contains(**marker))
        .count()
}

fn source_authority_override_for_low_priority_dominance(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
    signals: SourceSignalProfile,
) -> bool {
    if !source_has_public_authority_host(url) {
        return false;
    }
    if has_primary_status_authority(signals) {
        return true;
    }
    if source_document_authority_surface_hits(url, title, excerpt) > 0 {
        return true;
    }
    !observed_briefing_standard_identifier_labels(
        query_contract,
        &format!("{} {} {}", url, title, excerpt),
    )
    .is_empty()
}

fn source_low_priority_disqualifies_document_authority(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
    signals: SourceSignalProfile,
) -> bool {
    signals.low_priority_hits > 0
        || (signals.low_priority_dominates()
            && !source_authority_override_for_low_priority_dominance(
                query_contract,
                url,
                title,
                excerpt,
                signals,
            ))
}

fn source_requires_identifier_backed_document_authority(query_contract: &str) -> bool {
    query_prefers_document_briefing_layout(query_contract)
        && !query_requests_comparison(query_contract)
        && analyze_query_facets(query_contract).grounded_external_required
        && briefing_standard_identifier_group_floor(query_contract) > 0
}

fn source_has_identifier_backed_document_authority_evidence(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    source_has_briefing_standard_identifier_signal(query_contract, url, title, excerpt)
}

pub(crate) fn source_document_authority_score(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> usize {
    if source_has_human_challenge_signal(url, title, excerpt) {
        return 0;
    }
    let signals = analyze_source_record_signals(url, title, excerpt);
    if source_low_priority_disqualifies_document_authority(
        query_contract,
        url,
        title,
        excerpt,
        signals,
    ) {
        return 0;
    }
    if source_requires_identifier_backed_document_authority(query_contract)
        && !source_has_identifier_backed_document_authority_evidence(
            query_contract,
            url,
            title,
            excerpt,
        )
    {
        return 0;
    }

    let query_tokens = document_authority_query_tokens(query_contract);
    let host_tokens = document_authority_host_tokens(url);
    let title_tokens = normalized_anchor_tokens(title);
    let host_overlap = query_tokens.intersection(&host_tokens).count();
    let title_overlap = query_tokens.intersection(&title_tokens).count();
    let public_authority_host = usize::from(source_has_public_authority_host(url));
    let surface_hits = source_document_authority_surface_hits(url, title, excerpt).min(6);
    let primary_status_authority = usize::from(has_primary_status_authority(signals));

    host_overlap.saturating_mul(8)
        + title_overlap.saturating_mul(2)
        + public_authority_host.saturating_mul(6)
        + surface_hits.saturating_mul(2)
        + primary_status_authority.saturating_mul(4)
        + signals.provenance_hits.min(2)
}

pub(crate) fn source_has_document_authority(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if source_has_human_challenge_signal(url, title, excerpt) {
        return false;
    }
    let signals = analyze_source_record_signals(url, title, excerpt);
    if source_low_priority_disqualifies_document_authority(
        query_contract,
        url,
        title,
        excerpt,
        signals,
    ) {
        return false;
    }
    if source_requires_identifier_backed_document_authority(query_contract)
        && !source_has_identifier_backed_document_authority_evidence(
            query_contract,
            url,
            title,
            excerpt,
        )
    {
        return false;
    }
    if has_primary_status_authority(signals) {
        return true;
    }

    let query_tokens = document_authority_query_tokens(query_contract);
    let host_tokens = document_authority_host_tokens(url);
    let title_tokens = normalized_anchor_tokens(title);
    let host_overlap = query_tokens.intersection(&host_tokens).count();
    let title_overlap = query_tokens.intersection(&title_tokens).count();
    let public_authority_host = source_has_public_authority_host(url);
    let surface_hits = source_document_authority_surface_hits(url, title, excerpt);

    (host_overlap > 0 && (public_authority_host || surface_hits > 0 || title_overlap > 0))
        || (public_authority_host && surface_hits > 0)
}

pub(crate) fn is_document_authority_source(
    query_contract: &str,
    source: &PendingSearchReadSummary,
) -> bool {
    source_has_document_authority(
        query_contract,
        &source.url,
        source.title.as_deref().unwrap_or_default(),
        &source.excerpt,
    )
}

pub(crate) fn is_low_priority_coverage_story(source: &PendingSearchReadSummary) -> bool {
    source_evidence_signals(source).low_priority_dominates()
}

pub(crate) fn headline_source_is_low_quality(url: &str, title: &str, excerpt: &str) -> bool {
    if source_has_human_challenge_signal(url, title, excerpt) {
        return true;
    }
    let signals = analyze_source_record_signals(url, title, excerpt);
    let claim_signal_present = excerpt_has_claim_signal(excerpt);
    let actionable_signal_present = effective_primary_event_hits(signals) > 0
        || signals.impact_hits > 0
        || signals.mitigation_hits > 0;
    if signals.low_priority_hits > 0
        && !has_primary_status_authority(signals)
        && !claim_signal_present
        && !actionable_signal_present
    {
        return true;
    }
    if is_multi_item_listing_url(url) {
        return signals.low_priority_dominates();
    }
    signals.low_priority_dominates() && !has_primary_status_authority(signals)
}

pub(crate) fn is_low_signal_title(title: &str) -> bool {
    let trimmed = title.trim();
    if trimmed.is_empty() {
        return true;
    }
    if looks_like_structured_metadata_noise(trimmed) {
        return true;
    }
    let lower = trimmed.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "google news" | "news" | "home" | "homepage" | "untitled"
    ) || lower.starts_with("google news -")
        || lower.contains("breaking news, latest news")
        || lower.contains("today's latest headlines")
        || lower.contains("latest news and videos")
        || lower.contains("top stories")
}

pub(crate) fn headline_story_title_has_specificity(title: &str) -> bool {
    const GENERIC_TOKENS: &[&str] = &[
        "top",
        "news",
        "headline",
        "headlines",
        "latest",
        "breaking",
        "story",
        "stories",
        "update",
        "updates",
        "today",
        "live",
        "report",
        "reports",
        "listen",
        "watch",
        "now",
    ];

    let tokens = title
        .to_ascii_lowercase()
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .filter_map(|token| {
            let normalized = token.trim();
            if normalized.is_empty() {
                None
            } else {
                Some(normalized.to_string())
            }
        })
        .collect::<Vec<_>>();
    if tokens.len() < 2 {
        return false;
    }

    let informative_tokens = tokens
        .iter()
        .filter(|token| token.len() >= 3 && !GENERIC_TOKENS.contains(&token.as_str()))
        .count();
    informative_tokens >= 2
}

pub(crate) fn headline_title_is_multi_story_roundup_surface(title: &str) -> bool {
    let lower = title.trim().to_ascii_lowercase();
    if lower.is_empty() {
        return false;
    }
    [
        "top news headlines",
        "top headlines",
        "morning sprint",
        "newsminute",
        "news in a rush",
        "news and weather headlines",
    ]
    .iter()
    .any(|marker| lower.contains(marker))
}

pub(crate) fn headline_source_is_actionable(source: &PendingSearchReadSummary) -> bool {
    let url = source.url.trim();
    if url.is_empty() || is_search_hub_url(url) || is_multi_item_listing_url(url) {
        return false;
    }
    if headline_source_is_low_quality(
        url,
        source.title.as_deref().unwrap_or_default(),
        source.excerpt.as_str(),
    ) {
        return false;
    }

    let title = canonical_source_title(source);
    if is_low_signal_title(&title)
        || !headline_story_title_has_specificity(&title)
        || headline_title_is_multi_story_roundup_surface(&title)
    {
        return false;
    }
    if excerpt_has_claim_signal(&title) {
        return true;
    }

    let excerpt = source.excerpt.trim();
    if excerpt_has_claim_signal(excerpt) {
        return true;
    }
    let signals = source_evidence_signals(source);
    if effective_primary_event_hits(signals) > 0
        || signals.impact_hits > 0
        || signals.mitigation_hits > 0
    {
        return true;
    }

    true
}

pub(crate) fn headline_actionable_source_inventory(
    sources: &[PendingSearchReadSummary],
) -> (usize, usize) {
    let actionable = sources
        .iter()
        .filter(|source| headline_source_is_actionable(source))
        .cloned()
        .collect::<Vec<_>>();
    let distinct_domains = actionable
        .iter()
        .filter_map(|source| source_host(source.url.trim()))
        .map(|host| host.strip_prefix("www.").unwrap_or(&host).to_string())
        .collect::<BTreeSet<_>>()
        .len();
    (actionable.len(), distinct_domains)
}

pub(crate) fn actionable_source_signal_strength(signals: SourceSignalProfile) -> usize {
    effective_primary_event_hits(signals) + signals.impact_hits + signals.mitigation_hits
}

pub(crate) fn low_priority_source_signal_strength(signals: SourceSignalProfile) -> usize {
    signals.low_priority_hits + signals.secondary_coverage_hits + signals.documentation_surface_hits
}

pub(crate) fn effective_primary_event_hits(signals: SourceSignalProfile) -> usize {
    let surface_bias = signals
        .provenance_hits
        .max(signals.primary_status_surface_hits);
    signals
        .primary_event_hits
        .saturating_sub(surface_bias.min(signals.primary_event_hits))
}

pub(crate) fn excerpt_has_claim_signal(excerpt: &str) -> bool {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return false;
    }
    if looks_like_structured_metadata_noise(trimmed) {
        return false;
    }
    let metric_schema = analyze_metric_schema(trimmed);
    if metric_schema.has_metric_payload() || metric_schema.has_current_observation_payload() {
        return true;
    }
    let signals = analyze_source_record_signals("", "", trimmed);
    let has_timeline_claim = signals.timeline_hits > 0
        && (metric_schema.timestamp_hits > 0
            || (metric_schema.observation_hits > 0
                && trimmed.chars().any(|ch| ch.is_ascii_digit())));
    effective_primary_event_hits(signals) > 0
        || signals.impact_hits > 0
        || signals.mitigation_hits > 0
        || has_timeline_claim
}

pub(crate) fn excerpt_has_query_grounding_signal(
    query_contract: &str,
    min_sources: usize,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    excerpt_has_query_grounding_signal_with_contract(
        None,
        query_contract,
        min_sources,
        url,
        title,
        excerpt,
    )
}

pub(crate) fn excerpt_has_query_grounding_signal_with_contract(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query_contract: &str,
    min_sources: usize,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    let trimmed = excerpt.trim();
    if trimmed.is_empty()
        || looks_like_structured_metadata_noise(trimmed)
        || retrieval_contract_is_generic_headline_collection(retrieval_contract, query_contract)
    {
        return false;
    }

    let projection =
        build_query_constraint_projection(query_contract, min_sources.max(1) as u32, &[]);
    let current_price_required = projection
        .constraints
        .scopes
        .contains(&ConstraintScope::TimeSensitive)
        && projection
            .constraints
            .required_facets
            .contains(&MetricAxis::Price);
    if current_price_required && !has_price_quote_payload(trimmed) {
        return false;
    }

    if excerpt_has_claim_signal(trimmed) {
        return true;
    }

    if !projection.has_constraint_objective() {
        return false;
    }

    let source_tokens = source_anchor_tokens(url, title, trimmed);
    let query_anchor_overlap = projection.query_tokens.intersection(&source_tokens).count();
    let query_native_overlap = projection
        .query_native_tokens
        .intersection(&source_tokens)
        .count();
    let locality_overlap = projection
        .locality_tokens
        .intersection(&source_tokens)
        .count();
    let locality_satisfied = projection.locality_tokens.is_empty() || locality_overlap > 0;
    let signals = analyze_source_record_signals(url, title, trimmed);
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
        url,
        title,
        trimmed,
    );
    compatibility_passes_projection(&projection, &compatibility)
        || ((projection.query_facets.grounded_external_required
            || projection
                .constraints
                .scopes
                .contains(&ConstraintScope::TimeSensitive))
            && locality_satisfied
            && (query_anchor_overlap >= 2 || query_native_overlap >= 2))
}

pub(crate) fn excerpt_actionability_score(excerpt: &str) -> usize {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return 0;
    }

    let metric_schema = analyze_metric_schema(trimmed);
    let signals = analyze_source_record_signals("", "", trimmed);
    let has_claim_signal = excerpt_has_claim_signal(trimmed);
    let digit_hits = trimmed
        .chars()
        .filter(|ch| ch.is_ascii_digit())
        .count()
        .min(6);
    let actionability_signal = actionable_source_signal_strength(signals).min(8);
    let low_priority_signal = low_priority_source_signal_strength(signals).min(8);

    let mut score = 0usize;
    if metric_schema.has_current_observation_payload() {
        score = score.saturating_add(6);
    }
    if metric_schema.has_metric_payload() {
        score = score.saturating_add(4);
    }
    score = score
        .saturating_add(metric_schema.axis_hits.len().min(4).saturating_mul(2))
        .saturating_add(metric_schema.numeric_token_hits.min(4))
        .saturating_add(metric_schema.unit_hits.min(4))
        .saturating_add(metric_schema.observation_hits.min(3))
        .saturating_add(metric_schema.timestamp_hits.min(3));
    if has_claim_signal {
        let provenance_context = signals
            .provenance_hits
            .saturating_add(signals.primary_status_surface_hits)
            .saturating_add(signals.official_status_host_hits)
            .min(4);
        score = score
            .saturating_add(ACTIONABLE_EXCERPT_CLAIM_BASE_BONUS)
            .saturating_add(actionability_signal)
            .saturating_add(provenance_context);
    }
    score = score.saturating_add(digit_hits);
    score.saturating_sub(low_priority_signal)
}

pub(crate) fn is_low_signal_excerpt(excerpt: &str) -> bool {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return true;
    }
    if looks_like_structured_metadata_noise(trimmed) {
        return true;
    }
    if trimmed.chars().count() < ACTIONABLE_EXCERPT_SEGMENT_MIN_CHARS {
        return true;
    }
    let has_numeric_hint = trimmed.chars().any(|ch| ch.is_ascii_digit());
    if !excerpt_has_claim_signal(trimmed) && !has_numeric_hint {
        return true;
    }

    let actionability_score = excerpt_actionability_score(trimmed);
    if actionability_score >= ACTIONABLE_EXCERPT_MIN_SCORE {
        return false;
    }

    let anchor_token_count = normalized_anchor_tokens(trimmed).len();
    if !has_numeric_hint {
        return true;
    }
    anchor_token_count < 3
}

pub(crate) fn actionable_excerpt(excerpt: &str) -> Option<String> {
    let trimmed = excerpt.trim();
    if trimmed.is_empty() {
        return None;
    }
    let compact = compact_whitespace(trimmed);
    if compact.is_empty() {
        return None;
    }

    let mut best_segment: Option<(usize, String)> = None;
    for segment in compact
        .split(['.', '!', '?', ';'])
        .map(compact_whitespace)
        .filter(|value| !value.is_empty())
    {
        if looks_like_structured_metadata_noise(&segment) {
            continue;
        }
        if segment.chars().count() < ACTIONABLE_EXCERPT_SEGMENT_MIN_CHARS {
            continue;
        }
        if !excerpt_has_claim_signal(&segment) {
            continue;
        }
        let score = excerpt_actionability_score(&segment);
        if score < ACTIONABLE_EXCERPT_MIN_SCORE {
            continue;
        }
        let replace = best_segment
            .as_ref()
            .map(|(best_score, best_text)| {
                score > *best_score || (score == *best_score && segment.len() < best_text.len())
            })
            .unwrap_or(true);
        if replace {
            best_segment = Some((score, segment));
        }
    }

    if let Some((_, selected)) = best_segment {
        return Some(
            selected
                .chars()
                .take(WEB_PIPELINE_ACTIONABLE_EXCERPT_CHARS)
                .collect(),
        );
    }

    if excerpt_actionability_score(&compact) < ACTIONABLE_EXCERPT_MIN_SCORE
        || is_low_signal_excerpt(&compact)
    {
        return None;
    }

    Some(
        compact
            .chars()
            .take(WEB_PIPELINE_ACTIONABLE_EXCERPT_CHARS)
            .collect(),
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct UrlStructuralKey {
    pub(super) host: String,
    pub(super) path: String,
    pub(super) query_tokens: BTreeSet<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_terminal_error_signal_detects_not_found_page() {
        assert!(source_has_terminal_error_signal(
            "https://ny.eater.com/2023/10/5/23890123/best-italian-restaurants-nyc",
            "404 Not Found | Eater NY",
            "Sorry, the page you were looking for could not be found."
        ));
    }

    #[test]
    fn source_terminal_error_signal_detects_rate_limited_shell() {
        assert!(source_has_terminal_error_signal(
            "https://sentinelcolorado.com/nation-world/world/friday-news-in-a-rush-top-headlines-in-todays-newsminute-video-257/",
            "429 Too Many Requests",
            "429 Too Many Requests"
        ));
    }

    #[test]
    fn source_terminal_error_signal_ignores_valid_article_surface() {
        assert!(!source_has_terminal_error_signal(
            "https://www.theinfatuation.com/new-york/guides/best-italian-restaurants-nyc",
            "The Best Italian Restaurants In NYC",
            "A guide to standout Roman pasta, antipasti and house-made focaccia in New York."
        ));
    }

    #[test]
    fn source_human_challenge_signal_detects_security_checkpoint_interstitial() {
        assert!(source_has_human_challenge_signal(
            "https://www.hashicorp.com/en/blog/nist-s-post-quantum-cryptography-standards-our-plans",
            "Vercel Security Checkpoint",
            "Please complete the security check to continue."
        ));
    }

    #[test]
    fn headline_actionable_inventory_excludes_low_priority_roundups() {
        let sources = vec![
            PendingSearchReadSummary {
                url: "https://sundayguardianlive.com/news/school-assembly-news-headlines-today-march-05-top-national-business-news-sports-news-education-news-world-news-with-weather-updates-thought-of-the-day-174036/".to_string(),
                title: Some(
                    "School Assembly News Headlines Today March 05 Top National Business News Sports News Education News World News with Weather Updates Thought of the Day".to_string(),
                ),
                excerpt: "Daily roundup for school assembly with thought of the day and national headlines."
                    .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.today.com/parents/family/viral-teacher-tiktok-cursing-rule-rcna262092".to_string(),
                title: Some(
                    "High School Teacher Reveals The 1 Classroom Rule She No Longer Enforces After 25 Years".to_string(),
                ),
                excerpt: "Courtney Schermerhorn, a high school U.S. history teacher in Texas, says some classroom rules stop serving students after years of experience.".to_string(),
            },
        ];

        let (actionable_sources, actionable_domains) =
            headline_actionable_source_inventory(&sources);

        assert_eq!(actionable_sources, 1);
        assert_eq!(actionable_domains, 1);
        assert!(headline_source_is_actionable(&sources[1]));
        assert!(!headline_source_is_actionable(&sources[0]));
    }

    #[test]
    fn headline_source_is_actionable_when_title_carries_the_claim() {
        let source = PendingSearchReadSummary {
            url: "https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html".to_string(),
            title: Some(
                "Trump tariffs: Customs and Border Protection tells judge it can't comply with refund order - CNBC".to_string(),
            ),
            excerpt: "CNBC | source_url=https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html".to_string(),
        };

        assert!(
            headline_source_is_actionable(&source),
            "claim-bearing article titles should count as actionable headline evidence"
        );
    }

    #[test]
    fn headline_actionable_inventory_counts_specific_articles_with_sparse_snippets() {
        let sources = vec![
            PendingSearchReadSummary {
                url: "https://apnews.com/article/iran-sri-lanka-iris-bushehr-9b3c31177bf8bf8accf22cf3add241d7".to_string(),
                title: Some(
                    "Sri Lanka takes custody of an Iranian vessel off its coast after US sank an Iranian warship - AP News"
                        .to_string(),
                ),
                excerpt:
                    "AP News | source_url=https://apnews.com/article/iran-sri-lanka-iris-bushehr-9b3c31177bf8bf8accf22cf3add241d7"
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384".to_string(),
                title: Some(
                    "Mar 6: WAFCON Postponed, Uganda Evacuates 43 Students From Iran"
                        .to_string(),
                ),
                excerpt:
                    "OkayAfrica | source_url=https://www.okayafrica.com/today-in-africa-mar-6-2026-wafcon-postponed-uganda-evacuates-43-students-from-iran/1410384"
                        .to_string(),
            },
            PendingSearchReadSummary {
                url: "https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html".to_string(),
                title: Some(
                    "Trump tariffs: Customs and Border Protection tells judge it can't comply with refund order - CNBC".to_string(),
                ),
                excerpt:
                    "CNBC | source_url=https://www.cnbc.com/2026/03/06/trump-trade-tariffs-refunds-customs-border-protection.html"
                        .to_string(),
            },
        ];

        let (actionable_sources, actionable_domains) =
            headline_actionable_source_inventory(&sources);

        assert_eq!(actionable_sources, 3);
        assert_eq!(actionable_domains, 3);
    }

    #[test]
    fn headline_source_is_not_actionable_for_multi_story_roundup_surface() {
        let source = PendingSearchReadSummary {
            url: "https://www.channel3000.com/video/morning-sprint-march-6-mornings-top-news-and-weather-headlines/video_ae4a4a71-9eb5-5c14-a70a-908f6377ceaa.html".to_string(),
            title: Some(
                "Morning Sprint: March 6 morning's top news and weather headlines - Channel 3000"
                    .to_string(),
            ),
            excerpt: "Morning roundup video covering the day's top news and weather headlines."
                .to_string(),
        };

        assert!(
            !headline_source_is_actionable(&source),
            "multi-story roundup surfaces should not count as actionable headline stories"
        );
    }

    #[test]
    fn prioritized_query_grounding_excerpt_prefers_required_standard_identifier_segment() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let selected = prioritized_query_grounding_excerpt(
            query,
            3,
            "https://www.nist.gov/pqc",
            "Post-quantum cryptography | NIST",
            "NIST maintains post-quantum cryptography transition guidance for agencies. The Federal Information Processing Standards FIPS 203, FIPS 204, and FIPS 205 standardize ML-KEM, ML-DSA, and SLH-DSA for federal use. Agencies should inventory systems and plan migration timelines.",
            220,
        );

        assert!(
            selected.contains("FIPS 203")
                && selected.contains("FIPS 204")
                && selected.contains("FIPS 205"),
            "expected identifier-bearing segment, got: {selected:?}"
        );
    }

    #[test]
    fn prioritized_query_grounding_excerpt_combines_identifier_segments_when_needed() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let selected = prioritized_query_grounding_excerpt(
            query,
            3,
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards",
            "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST",
            "NIST finalized the first post-quantum encryption standards. Federal Information Processing Standard (FIPS) 203 specifies ML-KEM. The two digital signature standards are FIPS 204 and FIPS 205 for ML-DSA and SLH-DSA. Agencies should begin transition planning.",
            220,
        );

        assert!(
            selected.contains("FIPS 203")
                && selected.contains("FIPS 204")
                && selected.contains("FIPS 205"),
            "expected combined identifier-bearing excerpt, got: {selected:?}"
        );
    }

    #[test]
    fn observed_briefing_standard_identifier_labels_do_not_expand_query_specific_fips_sets() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let labels = observed_briefing_standard_identifier_labels(
            query,
            "NIST released FIPS 203, 204, and 205 as finalized post-quantum cryptography standards.",
        );

        assert!(labels.is_empty(), "labels={labels:?}");
    }

    #[test]
    fn source_document_authority_accepts_official_archive_news_with_query_grounding() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let url =
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards";
        let title = "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST";
        let excerpt = "August 13, 2024 - The finalized standards are FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography.";

        assert!(
            source_has_document_authority(query, url, title, excerpt),
            "official archive story should retain document authority despite archive-year surface"
        );
        assert!(source_document_authority_score(query, url, title, excerpt) > 0);
    }

    #[test]
    fn source_document_authority_rejects_generic_public_authority_surface_without_query_grounding()
    {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let url = "https://www.nist.gov/cybersecurity-and-privacy";
        let title = "Cybersecurity and Privacy | NIST";
        let excerpt = "NIST advances measurement science, standards, and technology for cybersecurity and privacy.";

        assert!(!source_has_document_authority(query, url, title, excerpt));
        assert_eq!(
            source_document_authority_score(query, url, title, excerpt),
            0
        );
    }

    #[test]
    fn source_document_authority_accepts_generic_authority_pages_when_discovery_signals_align() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let url = "https://www.nist.gov/pqc";
        let title = "Post-quantum cryptography | NIST";
        let excerpt =
            "NIST is advancing post-quantum cryptography standardization and transition guidance.";

        assert!(source_has_document_authority(query, url, title, excerpt));
        assert!(source_document_authority_score(query, url, title, excerpt) > 0);
    }

    #[test]
    fn prioritized_query_grounding_excerpt_anchors_long_segment_at_identifier_surface() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let selected = prioritized_query_grounding_excerpt(
            query,
            3,
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards",
            "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST",
            "Official websites use .gov and secure HTTPS connections for official government information and services. This page explains the update. NIST released FIPS 203, 204, and 205 as the first finalized post-quantum encryption standards for federal use and transition planning.",
            120,
        );

        assert!(
            selected.contains("FIPS 203") && selected.contains("204") && selected.contains("205"),
            "expected identifier-anchored excerpt, got: {selected:?}"
        );
        assert!(
            !selected.starts_with("Official websites use"),
            "expected identifier-focused excerpt, got: {selected:?}"
        );
    }

    #[test]
    fn prioritized_query_grounding_excerpt_preserves_menu_inventory_for_menu_comparisons() {
        let query =
            "Find the three best-reviewed Italian restaurants in Anderson, SC and compare their menus.";
        let retrieval_contract =
            crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
                .expect("retrieval contract");
        let selected = prioritized_query_grounding_excerpt_with_contract(
            Some(&retrieval_contract),
            query,
            3,
            "https://www.restaurantji.com/sc/anderson/brothers-italian-cuisine-/menu/",
            "Menu",
            "Item inventory includes Brothers Special Shrimp Pasta, Chef Salad, Italian Stromboli, Grilled Chicken Salad, and Meat Lovers Calzone. Related image gallery available with 6 images. Brothers Special Shrimp Pasta. Chef Salad.",
            240,
        );

        assert!(selected.contains("Item inventory includes"));
        assert!(selected.contains("Related image gallery available with 6 images."));
    }
}
