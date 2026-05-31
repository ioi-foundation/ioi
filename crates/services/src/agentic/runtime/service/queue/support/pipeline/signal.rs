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

const HUMAN_CHALLENGE_EXCERPT_PROBE_CHARS: usize = 220;

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

mod evidence_identifiers;
pub(crate) use evidence_identifiers::*;

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
    fn host_anchored_pricing_metric_segment_score(segment: &str) -> i32 {
        let lowered = format!(" {} ", compact_whitespace(segment).to_ascii_lowercase());
        let mut score = metric_segment_signal_score(segment) as i32;
        let api_pricing_markers = [
            " input",
            " output",
            " cached",
            " token",
            " tokens",
            " prompt",
            " completion",
            " image",
            " text",
            " audio",
            " video",
            " realtime",
            " model",
            " models",
            " gpt",
        ];
        let api_marker_hits = api_pricing_markers
            .iter()
            .filter(|marker| lowered.contains(**marker))
            .count() as i32;
        score += api_marker_hits.min(4) * 8;

        let storage_markers = [
            " gb ",
            " container",
            " containers",
            " session",
            " sessions",
            " minute",
            " minutes",
            " duration",
            " storage",
        ];
        let storage_marker_hits = storage_markers
            .iter()
            .filter(|marker| lowered.contains(**marker))
            .count() as i32;
        if storage_marker_hits > 0 {
            if api_marker_hits == 0 {
                score -= storage_marker_hits.min(3) * 10;
            } else {
                score -= storage_marker_hits.min(3) * 4;
            }
        }
        if lowered.contains(" now: ") && api_marker_hits == 0 {
            score -= 10;
        }
        score
    }

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

    let current_metric_surface_required = retrieval_contract
        .map(|contract| contract.currentness_required)
        .unwrap_or(false)
        || analyze_query_facets(query_contract).time_sensitive_public_fact;
    if current_metric_surface_required {
        let metric_excerpt = if query_requires_host_anchored_primary_authority(query_contract) {
            metric_sentence_like_segments(input)
                .into_iter()
                .filter(|segment| analyze_metric_schema(segment).has_metric_payload())
                .filter(|segment| candidate_time_sensitive_resolvable_payload(url, title, segment))
                .max_by_key(|segment| {
                    let mut score = host_anchored_pricing_metric_segment_score(segment);
                    if contains_current_condition_metric_signal(segment) {
                        score += 12;
                    }
                    if excerpt_has_query_grounding_signal_with_contract(
                        retrieval_contract,
                        query_contract,
                        min_sources,
                        url,
                        title,
                        segment,
                    ) {
                        score += 6;
                    }
                    score
                })
        } else {
            first_metric_sentence(input).or_else(|| best_metric_segment(input))
        };
        if let Some(metric_excerpt) = metric_excerpt {
            let mut focused_metric_excerpt = compact_metric_focus(&metric_excerpt);
            if focused_metric_excerpt.chars().any(|ch| ch.is_ascii_digit())
                && (focused_metric_excerpt.contains('$')
                    || focused_metric_excerpt.to_ascii_lowercase().contains("usd"))
                && !contains_current_condition_metric_signal(&focused_metric_excerpt)
            {
                let labeled_metric_excerpt = format!("Pricing: {focused_metric_excerpt}");
                if contains_current_condition_metric_signal(&labeled_metric_excerpt) {
                    focused_metric_excerpt = labeled_metric_excerpt;
                }
            }
            if !focused_metric_excerpt.is_empty()
                && candidate_time_sensitive_resolvable_payload(url, title, &focused_metric_excerpt)
                && excerpt_has_query_grounding_signal_with_contract(
                    retrieval_contract,
                    query_contract,
                    min_sources,
                    url,
                    title,
                    &focused_metric_excerpt,
                )
            {
                return focused_metric_excerpt;
            }
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
    let excerpt_probe = compact_excerpt(excerpt, HUMAN_CHALLENGE_EXCERPT_PROBE_CHARS);
    let surface = format!("{} {} {}", url, title, excerpt_probe).to_ascii_lowercase();
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

pub(crate) fn document_authority_query_tokens(query_contract: &str) -> BTreeSet<String> {
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

pub(crate) fn query_requires_host_anchored_primary_authority(query_contract: &str) -> bool {
    let normalized = query_contract.to_ascii_lowercase();
    (normalized.contains("pricing")
        || normalized.contains("billing")
        || normalized.contains("price per")
        || normalized.contains("rate card")
        || normalized.contains("token cost"))
        && (normalized.contains("api")
            || normalized.contains("model")
            || normalized.contains("service")
            || normalized.contains("platform")
            || normalized.contains("official"))
}

fn query_host_anchor_tokens(query_contract: &str) -> BTreeSet<String> {
    query_contract
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter_map(|token| {
            let normalized = token.trim().to_ascii_lowercase();
            if normalized.len() < 4 {
                return None;
            }
            if matches!(
                normalized.as_str(),
                "what"
                    | "when"
                    | "where"
                    | "which"
                    | "latest"
                    | "current"
                    | "right"
                    | "pricing"
                    | "billing"
                    | "price"
                    | "prices"
                    | "token"
                    | "tokens"
                    | "cost"
                    | "costs"
                    | "rate"
                    | "rates"
                    | "card"
                    | "cards"
                    | "official"
                    | "open"
                    | "api"
                    | "apis"
                    | "model"
                    | "models"
                    | "service"
                    | "services"
                    | "platform"
            ) {
                return None;
            }
            Some(normalized)
        })
        .collect()
}

fn source_matches_host_anchored_primary_authority(query_contract: &str, url: &str) -> bool {
    let tokens = query_host_anchor_tokens(query_contract);
    !tokens.is_empty()
        && document_authority_host_tokens(url)
            .into_iter()
            .any(|token| tokens.contains(&token))
}

pub(crate) fn source_has_public_authority_host(url: &str) -> bool {
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
    !observed_evidence_standard_identifier_labels(
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
    query_prefers_document_report_layout(query_contract)
        && !query_requests_comparison(query_contract)
        && analyze_query_facets(query_contract).grounded_external_required
        && evidence_standard_identifier_group_floor(query_contract) > 0
}

fn source_has_identifier_backed_document_authority_evidence(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    source_has_evidence_standard_identifier_signal(query_contract, url, title, excerpt)
}

fn document_authority_subject_query_tokens(query_contract: &str) -> BTreeSet<String> {
    query_native_anchor_tokens(query_contract)
        .into_iter()
        .filter(|token| token.len() >= 4)
        .filter(|token| {
            !matches!(
                token.as_str(),
                "latest"
                    | "current"
                    | "today"
                    | "briefing"
                    | "overview"
                    | "summary"
                    | "research"
                    | "write"
                    | "page"
                    | "pages"
                    | "official"
                    | "public"
                    | "source"
                    | "sources"
                    | "standard"
                    | "standards"
                    | "guidance"
                    | "transition"
                    | "migration"
            )
        })
        .collect()
}

fn source_has_document_authority_subject_grounding(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    let query_tokens = document_authority_subject_query_tokens(query_contract);
    if query_tokens.is_empty() {
        return true;
    }
    let source_tokens = source_anchor_tokens(url, title, excerpt);
    query_tokens.intersection(&source_tokens).count() >= 2
}

fn source_lacks_required_document_subject_grounding(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
    signals: SourceSignalProfile,
) -> bool {
    query_prefers_document_report_layout(query_contract)
        && !query_requests_comparison(query_contract)
        && analyze_query_facets(query_contract).grounded_external_required
        && !has_primary_status_authority(signals)
        && !source_has_identifier_backed_document_authority_evidence(
            query_contract,
            url,
            title,
            excerpt,
        )
        && !source_has_document_authority_subject_grounding(query_contract, url, title, excerpt)
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
    if source_lacks_required_document_subject_grounding(
        query_contract,
        url,
        title,
        excerpt,
        signals,
    ) {
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
    if source_lacks_required_document_subject_grounding(
        query_contract,
        url,
        title,
        excerpt,
        signals,
    ) {
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

pub(crate) fn source_counts_as_primary_authority(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if !source_has_document_authority(query_contract, url, title, excerpt) {
        return false;
    }
    if query_requires_host_anchored_primary_authority(query_contract) {
        return source_matches_host_anchored_primary_authority(query_contract, url);
    }
    true
}

pub(crate) fn source_has_host_anchored_primary_authority_snapshot_alignment(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query_contract: &str,
    min_sources: usize,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    query_requires_host_anchored_primary_authority(query_contract)
        && retrieval_contract_requires_primary_authority_source(retrieval_contract, query_contract)
        && source_counts_as_primary_authority(query_contract, url, title, excerpt)
        && candidate_time_sensitive_resolvable_payload(url, title, excerpt)
        && (!title.trim().is_empty()
            || !excerpt.trim().is_empty()
            || excerpt_has_query_grounding_signal_with_contract(
                retrieval_contract,
                query_contract,
                min_sources,
                url,
                title,
                excerpt,
            ))
}

pub(crate) fn source_has_grounded_primary_authority(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if !source_has_document_authority(query_contract, url, title, excerpt) {
        return false;
    }

    let identifier_bearing =
        source_has_evidence_standard_identifier_signal(query_contract, url, title, excerpt);
    let source_tokens = source_anchor_tokens(url, title, excerpt);
    let query_native_overlap = query_native_anchor_tokens(query_contract)
        .intersection(&source_tokens)
        .count();
    let strong_subject_overlap = query_native_overlap >= 3
        || (query_native_overlap >= 2 && source_temporal_recency_score(url, title, excerpt) > 0);

    strong_subject_overlap || identifier_bearing
}

pub(crate) fn source_is_grounded_external_publication_support_artifact(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if !query_prefers_document_report_layout(query_contract)
        || query_requests_comparison(query_contract)
        || !analyze_query_facets(query_contract).grounded_external_required
        || !retrieval_contract
            .map(|contract| contract.currentness_required || contract.source_independence_min > 1)
            .unwrap_or(false)
    {
        return false;
    }

    let trimmed = url.trim();
    if trimmed.is_empty()
        || !is_citable_web_url(trimmed)
        || source_has_public_authority_host(trimmed)
    {
        return false;
    }
    if title.trim().is_empty() && excerpt.trim().is_empty() {
        return false;
    }
    if source_has_human_challenge_signal(trimmed, title, excerpt) {
        return false;
    }

    let Ok(parsed) = Url::parse(trimmed) else {
        return false;
    };
    if !parsed.path().to_ascii_lowercase().ends_with(".pdf") {
        return false;
    }

    let signals = analyze_source_record_signals(trimmed, title, excerpt);
    if signals.low_priority_hits > 0 || signals.low_priority_dominates() {
        return false;
    }

    let source_tokens = source_anchor_tokens(trimmed, title, excerpt);
    let native_overlap = query_native_anchor_tokens(query_contract)
        .intersection(&source_tokens)
        .count();
    let semantic_query_tokens = query_semantic_anchor_tokens(query_contract);
    let semantic_overlap = semantic_query_tokens.intersection(&source_tokens).count();
    let pqc_shorthand_overlap = source_tokens.contains("pqc")
        && semantic_query_tokens.contains("post")
        && semantic_query_tokens.contains("quantum")
        && semantic_query_tokens.contains("cryptography");

    native_overlap >= 2 || semantic_overlap >= 2 || pqc_shorthand_overlap
}

pub(crate) fn source_has_document_report_authority_alignment_with_contract(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query_contract: &str,
    min_sources: usize,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if !query_prefers_document_report_layout(query_contract) {
        return false;
    }

    let identifier_surface_grounded = source_has_public_authority_host(url)
        && source_has_evidence_standard_identifier_signal(query_contract, url, title, excerpt)
        && query_native_anchor_tokens(query_contract)
            .intersection(&source_anchor_tokens(url, title, excerpt))
            .count()
            >= 2;
    let grounded_document_report_query = !query_requests_comparison(query_contract)
        && analyze_query_facets(query_contract).grounded_external_required;

    if grounded_document_report_query
        && (source_has_grounded_primary_authority(query_contract, url, title, excerpt)
            || identifier_surface_grounded)
    {
        return true;
    }

    if query_requests_comparison(query_contract) {
        return false;
    }

    retrieval_contract.is_some_and(|contract| contract.currentness_required)
        && analyze_query_facets(query_contract).grounded_external_required
        && source_has_public_authority_host(url)
        && excerpt_has_query_grounding_signal_with_contract(
            retrieval_contract,
            query_contract,
            min_sources,
            url,
            title,
            excerpt,
        )
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

pub(crate) fn is_low_priority_coverage_source(source: &PendingSearchReadSummary) -> bool {
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
    let article_like_source_surface = looks_like_deep_article_url(url)
        && !is_multi_item_listing_url(url)
        && headline_source_title_has_specificity(title)
        && !headline_title_is_multi_source_roundup_surface(title);
    if article_like_source_surface && (claim_signal_present || actionable_signal_present) {
        return false;
    }
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

pub(crate) fn headline_source_title_has_specificity(title: &str) -> bool {
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

pub(crate) fn headline_title_is_multi_source_roundup_surface(title: &str) -> bool {
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
        || !headline_source_title_has_specificity(&title)
        || headline_title_is_multi_source_roundup_surface(&title)
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
    if looks_like_structured_metadata_noise(trimmed) {
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
#[path = "signal/tests.rs"]
mod tests;
