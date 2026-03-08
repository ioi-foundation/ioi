use super::*;

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
    if ["cookie':'", "cookie\":\"", "set-cookie", "cf_clearance"]
        .iter()
        .any(|marker| lower.contains(marker))
    {
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
    [
        "please enable js",
        "please enable javascript",
        "enable javascript",
        "verify you are human",
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
}
