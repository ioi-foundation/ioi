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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CanonicalIdentifierGroup {
    pub(crate) key: &'static str,
    pub(crate) primary_label: &'static str,
    pub(crate) required: bool,
    pub(crate) needles: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BriefingIdentifierObservation {
    pub(crate) url: String,
    pub(crate) surface: String,
    pub(crate) authoritative: bool,
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

fn is_briefing_fips_number(token: &str) -> bool {
    token.len() == 3 && token.chars().all(|ch| ch.is_ascii_digit())
}

fn is_briefing_ir_number(token: &str) -> bool {
    (3..=5).contains(&token.len()) && token.chars().all(|ch| ch.is_ascii_digit())
}

fn parse_briefing_ir_number(token: &str) -> Option<usize> {
    is_briefing_ir_number(token)
        .then(|| token.parse::<usize>().ok())
        .flatten()
}

fn is_year_like_ir_directory(number: usize) -> bool {
    (2000..=2100).contains(&number)
}

fn briefing_identifier_sort_key(label: &str) -> (usize, usize, String) {
    let trimmed = compact_whitespace(label);
    let lower = trimmed.to_ascii_lowercase();
    if let Some(number) = lower
        .strip_prefix("fips ")
        .and_then(|value| value.parse::<usize>().ok())
    {
        return (0, number, lower);
    }
    if let Some(number) = lower
        .strip_prefix("ir ")
        .and_then(|value| value.parse::<usize>().ok())
    {
        return (1, number, lower);
    }
    (2, 0, lower)
}

fn sort_briefing_identifier_labels<I>(labels: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut ordered = labels.into_iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        briefing_identifier_sort_key(left).cmp(&briefing_identifier_sort_key(right))
    });
    ordered
}

fn observed_generic_briefing_standard_identifier_labels(surface: &str) -> Vec<String> {
    let normalized_surface = normalized_identifier_surface(surface);
    if normalized_surface.is_empty() {
        return Vec::new();
    }

    let tokens = normalized_surface.split_whitespace().collect::<Vec<_>>();
    let mut labels = BTreeSet::new();
    let mut idx = 0usize;
    while idx < tokens.len() {
        if tokens[idx] == "ir" {
            if let Some(token) = tokens.get(idx + 1).copied() {
                if let Some(number) = parse_briefing_ir_number(token) {
                    if is_year_like_ir_directory(number) {
                        let mut recovered = None;
                        let lookahead_end = idx.saturating_add(6).min(tokens.len());
                        let mut cursor = idx + 2;
                        while cursor + 1 < lookahead_end {
                            if tokens[cursor] == "ir" {
                                if let Some(next_token) = tokens.get(cursor + 1).copied() {
                                    if let Some(next_number) = parse_briefing_ir_number(next_token)
                                    {
                                        if !is_year_like_ir_directory(next_number) {
                                            recovered = Some((cursor + 2, next_token));
                                            break;
                                        }
                                    }
                                }
                            }
                            cursor += 1;
                        }
                        if let Some((next_idx, next_token)) = recovered {
                            labels.insert(format!("IR {}", next_token));
                            idx = next_idx;
                            continue;
                        }
                        idx += 2;
                        continue;
                    }
                    labels.insert(format!("IR {}", token));
                    idx += 2;
                    continue;
                }
            }
            idx += 1;
            continue;
        }

        if tokens[idx] != "fips" {
            idx += 1;
            continue;
        }

        let mut cursor = idx + 1;
        let mut saw_identifier = false;
        while cursor < tokens.len() {
            let token = tokens[cursor];
            if is_briefing_fips_number(token) {
                labels.insert(format!("FIPS {}", token));
                saw_identifier = true;
                cursor += 1;
                continue;
            }
            if matches!(token, "and" | "or" | "plus") {
                cursor += 1;
                continue;
            }
            break;
        }

        if saw_identifier {
            idx = cursor;
            continue;
        }
        idx += 1;
    }

    sort_briefing_identifier_labels(labels)
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
    let static_labels = observed_briefing_standard_identifier_groups(query_contract, surface)
        .into_iter()
        .map(|group| group.primary_label.to_string())
        .collect::<BTreeSet<_>>();
    let generic_labels = observed_generic_briefing_standard_identifier_labels(surface)
        .into_iter()
        .collect::<BTreeSet<_>>();
    sort_briefing_identifier_labels(static_labels.into_iter().chain(generic_labels))
}

pub(crate) fn preferred_source_briefing_identifier_surface(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> String {
    let primary_surface = compact_whitespace(&format!("{url} {title}"));
    if !primary_surface.is_empty()
        && !observed_briefing_standard_identifier_labels(query_contract, &primary_surface)
            .is_empty()
    {
        return primary_surface;
    }

    compact_whitespace(&format!("{url} {title} {excerpt}"))
}

pub(crate) fn source_briefing_standard_identifier_labels(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> BTreeSet<String> {
    observed_briefing_standard_identifier_labels(
        query_contract,
        &preferred_source_briefing_identifier_surface(query_contract, url, title, excerpt),
    )
    .into_iter()
    .collect()
}

fn is_authority_family_variant_token(token: &str) -> bool {
    matches!(token, "final" | "draft" | "latest" | "index")
        || ["upd", "update", "rev", "revision", "v"]
            .iter()
            .any(|prefix| {
                token.strip_prefix(prefix).is_some_and(|rest| {
                    !rest.is_empty() && rest.chars().all(|ch| ch.is_ascii_digit())
                })
            })
}

fn normalized_authority_family_title_key(title: &str) -> String {
    normalized_identifier_surface(title)
}

fn normalized_authority_family_url_key(url: &str) -> String {
    let Ok(parsed) = Url::parse(url.trim()) else {
        return String::new();
    };
    let Some(host) = parsed
        .host_str()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return String::new();
    };
    let mut segments = parsed
        .path_segments()
        .into_iter()
        .flatten()
        .map(|segment| {
            let mut tokens = normalized_identifier_surface(segment)
                .split_whitespace()
                .filter(|token| !matches!(*token, "pdf" | "html" | "htm"))
                .map(str::to_string)
                .collect::<Vec<_>>();
            while tokens
                .last()
                .is_some_and(|token| is_authority_family_variant_token(token))
            {
                tokens.pop();
            }
            tokens.join("-")
        })
        .filter(|segment| !segment.is_empty())
        .collect::<Vec<_>>();
    while segments
        .last()
        .is_some_and(|segment| is_authority_family_variant_token(segment))
    {
        segments.pop();
    }
    if segments.is_empty() {
        return host.to_ascii_lowercase();
    }
    format!("{}/{}", host.to_ascii_lowercase(), segments.join("/"))
}

pub(crate) fn source_document_authority_family_key(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> Option<String> {
    let title_key = normalized_authority_family_title_key(title);
    if !title_key.is_empty() {
        return Some(format!("title:{title_key}"));
    }

    let url_key = normalized_authority_family_url_key(url);
    if !url_key.is_empty() {
        return Some(format!("url:{url_key}"));
    }

    let identifier_labels = sort_briefing_identifier_labels(
        source_briefing_standard_identifier_labels(query_contract, url, title, excerpt),
    );
    if !identifier_labels.is_empty() {
        return Some(format!(
            "briefing-identifier:{}",
            identifier_labels.join("|")
        ));
    }

    let surface_key = normalized_identifier_surface(&preferred_source_briefing_identifier_surface(
        query_contract,
        url,
        title,
        excerpt,
    ));
    if !surface_key.is_empty() {
        return Some(format!("surface:{surface_key}"));
    }

    None
}

pub(crate) fn source_has_briefing_standard_identifier_signal(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    !source_briefing_standard_identifier_labels(query_contract, url, title, excerpt).is_empty()
}

fn parse_temporal_year_token(token: &str) -> Option<usize> {
    (token.len() == 4)
        .then(|| token.parse::<usize>().ok())
        .flatten()
        .filter(|year| (2000..=2100).contains(year))
}

fn parse_temporal_day_token(token: &str) -> Option<usize> {
    token
        .parse::<usize>()
        .ok()
        .filter(|value| (1..=31).contains(value))
}

fn parse_temporal_month_token(token: &str) -> Option<usize> {
    match token {
        "january" => Some(1),
        "february" => Some(2),
        "march" => Some(3),
        "april" => Some(4),
        "may" => Some(5),
        "june" => Some(6),
        "july" => Some(7),
        "august" => Some(8),
        "september" => Some(9),
        "october" => Some(10),
        "november" => Some(11),
        "december" => Some(12),
        _ => token
            .parse::<usize>()
            .ok()
            .filter(|value| (1..=12).contains(value)),
    }
}

fn temporal_recency_score_from_surface(surface: &str) -> usize {
    let normalized = surface.to_ascii_lowercase();
    let tokens = normalized
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .collect::<Vec<_>>();
    let mut best = 0usize;

    for (idx, token) in tokens.iter().enumerate() {
        if let Some(year) = parse_temporal_year_token(token) {
            best = best.max(year.saturating_mul(10_000));
            if let Some(month) = tokens
                .get(idx + 1)
                .and_then(|token| parse_temporal_month_token(token))
            {
                let day = tokens
                    .get(idx + 2)
                    .and_then(|token| parse_temporal_day_token(token))
                    .unwrap_or(0);
                best = best.max(
                    year.saturating_mul(10_000)
                        .saturating_add(month.saturating_mul(100))
                        .saturating_add(day),
                );
            }
        }

        if let Some(month) = parse_temporal_month_token(token) {
            if let Some(day) = tokens
                .get(idx + 1)
                .and_then(|token| parse_temporal_day_token(token))
            {
                if let Some(year) = tokens
                    .get(idx + 2)
                    .and_then(|token| parse_temporal_year_token(token))
                {
                    best = best.max(
                        year.saturating_mul(10_000)
                            .saturating_add(month.saturating_mul(100))
                            .saturating_add(day),
                    );
                }
            } else if let Some(year) = tokens
                .get(idx + 1)
                .and_then(|token| parse_temporal_year_token(token))
            {
                best = best.max(
                    year.saturating_mul(10_000)
                        .saturating_add(month.saturating_mul(100)),
                );
            }
        }
    }

    best
}

pub(crate) fn source_temporal_recency_score(url: &str, title: &str, excerpt: &str) -> usize {
    temporal_recency_score_from_surface(url)
        .max(temporal_recency_score_from_surface(title))
        .max(temporal_recency_score_from_surface(excerpt))
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
        || lower.contains("document.queryselector")
        || lower.contains("crypto.getrandomvalues")
        || (lower.contains("function")
            && (lower.contains("return function")
                || lower.contains("{c()[")
                || lower.contains("}function ")))
        || (lower.contains("return")
            && lower.contains("=>")
            && (lower.contains("document.") || lower.contains("crypto.")))
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
    let compact = compact_whitespace(input);
    if compact.is_empty() || looks_like_structured_metadata_noise(&compact) {
        return String::new();
    }
    if observed_briefing_standard_identifier_labels(query_contract, &compact).is_empty() {
        return String::new();
    }

    #[derive(Clone)]
    struct IdentifierSegment {
        text: String,
        required_labels: BTreeSet<String>,
        total_hits: usize,
        authority_marker_hits: usize,
    }

    let inferred_labels = observed_briefing_standard_identifier_labels(query_contract, &compact)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let required_floor = inferred_labels.len();
    let mut segments = compact
        .split(['.', '!', '?', ';', '\n'])
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .filter_map(|segment| {
            let observed_labels =
                observed_briefing_standard_identifier_labels(query_contract, segment)
                    .into_iter()
                    .collect::<BTreeSet<_>>();
            if observed_labels.is_empty() {
                return None;
            }
            let candidate = compact_whitespace(segment);
            if candidate.is_empty() {
                return None;
            }
            Some(IdentifierSegment {
                text: candidate,
                required_labels: observed_labels,
                total_hits: observed_briefing_standard_identifier_labels(query_contract, segment)
                    .len(),
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
        let anchor = observed_briefing_standard_identifier_labels(query_contract, segment)
            .into_iter()
            .filter_map(|label| lower.find(&label.to_ascii_lowercase()))
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

fn surface_tokens_preserving_hyphen(surface: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut current = String::new();
    for ch in surface.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' {
            current.push(ch);
            continue;
        }
        if !current.is_empty() {
            tokens.push(current.clone());
            current.clear();
        }
    }
    if !current.is_empty() {
        tokens.push(current);
    }
    tokens
}

fn token_is_uppercase_alias(token: &str) -> bool {
    token.contains('-')
        && token.chars().any(|ch| ch.is_ascii_uppercase())
        && token
            .chars()
            .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '-')
}

fn preferred_briefing_identifier_alias(label: &str, surface: &str) -> Option<String> {
    let target = label
        .to_ascii_lowercase()
        .strip_prefix("fips ")
        .map(str::to_string)?;
    let normalized = normalized_identifier_surface(surface);
    let normalized_tokens = normalized.split_whitespace().collect::<Vec<_>>();
    let raw_tokens = surface_tokens_preserving_hyphen(surface);
    let max_pairs = normalized_tokens.len().min(raw_tokens.len());
    for idx in 0..max_pairs {
        if normalized_tokens[idx] != "fips"
            || normalized_tokens.get(idx + 1) != Some(&target.as_str())
        {
            continue;
        }
        let raw_start = idx.saturating_add(2);
        if raw_start >= raw_tokens.len() {
            continue;
        }
        let raw_end = (raw_start + 10).min(raw_tokens.len());
        for token in &raw_tokens[raw_start..raw_end] {
            if token_is_uppercase_alias(token) {
                return Some(token.trim_matches('-').to_string());
            }
        }
    }
    None
}

pub(crate) fn infer_briefing_required_identifier_labels(
    query_contract: &str,
    observations: &[BriefingIdentifierObservation],
) -> BTreeSet<String> {
    if !query_prefers_document_briefing_layout(query_contract)
        || query_requests_comparison(query_contract)
    {
        return BTreeSet::new();
    }

    let mut total_sources_by_label = BTreeMap::<String, BTreeSet<String>>::new();
    let mut authority_sources_by_label = BTreeMap::<String, BTreeSet<String>>::new();
    let mut multi_identifier_authority_sets = Vec::<BTreeSet<String>>::new();
    for observation in observations {
        let normalized_url = crate::agentic::web::normalize_url_for_id(&observation.url);
        if normalized_url.trim().is_empty() {
            continue;
        }
        let labels =
            observed_briefing_standard_identifier_labels(query_contract, &observation.surface)
                .into_iter()
                .collect::<BTreeSet<_>>();
        if labels.is_empty() {
            continue;
        }
        for label in &labels {
            total_sources_by_label
                .entry(label.clone())
                .or_default()
                .insert(normalized_url.clone());
            if observation.authoritative {
                authority_sources_by_label
                    .entry(label.clone())
                    .or_default()
                    .insert(normalized_url.clone());
            }
        }
        if observation.authoritative && labels.len() >= 2 {
            multi_identifier_authority_sets.push(labels);
        }
    }

    let mut inferred = total_sources_by_label
        .iter()
        .filter_map(|(label, sources)| {
            let authority_count = authority_sources_by_label
                .get(label)
                .map(|urls| urls.len())
                .unwrap_or(0);
            ((sources.len() >= 2) || authority_count >= 2).then(|| label.clone())
        })
        .collect::<BTreeSet<_>>();

    if let Some(best_authority_set) =
        multi_identifier_authority_sets
            .into_iter()
            .max_by(|left, right| {
                left.len().cmp(&right.len()).then_with(|| {
                    sort_briefing_identifier_labels(right.iter().cloned())
                        .cmp(&sort_briefing_identifier_labels(left.iter().cloned()))
                })
            })
    {
        if inferred.is_empty()
            || inferred
                .iter()
                .any(|label| best_authority_set.contains(label))
        {
            inferred.extend(best_authority_set);
        }
    }

    inferred
}

pub(crate) fn inferred_briefing_identifier_group_floor(
    query_contract: &str,
    observations: &[BriefingIdentifierObservation],
) -> usize {
    infer_briefing_required_identifier_labels(query_contract, observations).len()
}

pub(crate) fn preferred_briefing_identifier_display_labels(
    labels: impl IntoIterator<Item = String>,
    observations: &[BriefingIdentifierObservation],
) -> Vec<String> {
    sort_briefing_identifier_labels(labels)
        .into_iter()
        .map(|label| {
            observations
                .iter()
                .filter_map(|observation| {
                    preferred_briefing_identifier_alias(&label, &observation.surface).map(|alias| {
                        (
                            observation.authoritative,
                            observation.surface.len(),
                            format!("{label} ({alias})"),
                        )
                    })
                })
                .max_by(|left, right| left.cmp(right))
                .map(|(_, _, display)| display)
                .unwrap_or(label)
        })
        .collect()
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
        source_has_briefing_standard_identifier_signal(query_contract, url, title, excerpt);
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
    if !query_prefers_document_briefing_layout(query_contract)
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

pub(crate) fn source_has_document_briefing_authority_alignment_with_contract(
    retrieval_contract: Option<&ioi_types::app::agentic::WebRetrievalContract>,
    query_contract: &str,
    min_sources: usize,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    if !query_prefers_document_briefing_layout(query_contract) {
        return false;
    }

    let identifier_surface_grounded = source_has_public_authority_host(url)
        && source_has_briefing_standard_identifier_signal(query_contract, url, title, excerpt)
        && query_native_anchor_tokens(query_contract)
            .intersection(&source_anchor_tokens(url, title, excerpt))
            .count()
            >= 2;
    let grounded_document_briefing_query = !query_requests_comparison(query_contract)
        && analyze_query_facets(query_contract).grounded_external_required;

    if grounded_document_briefing_query
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
    let article_like_story_surface = looks_like_deep_article_url(url)
        && !is_multi_item_listing_url(url)
        && headline_story_title_has_specificity(title)
        && !headline_title_is_multi_story_roundup_surface(title);
    if article_like_story_surface && (claim_signal_present || actionable_signal_present) {
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
    fn source_human_challenge_signal_ignores_late_body_markers_in_official_document() {
        assert!(!source_has_human_challenge_signal(
            "https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf",
            "Migration to Post-Quantum Cryptography | NCCoE",
            "NIST SPECIAL PUBLICATION 1800-38C Migration to Post-Quantum Cryptography Quantum Readiness: Testing Draft Standards. Volume C: Quantum-Resistant Cryptography Technology Interoperability and Performance Report. National Institute of Standards and Technology. Appendix example browser message for test data only: access denied due to captcha."
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
    fn preferred_briefing_identifier_alias_ignores_trailing_match_when_raw_tokens_are_shorter() {
        assert_eq!(
            preferred_briefing_identifier_alias("FIPS 204", "PQC ML-DSA FIPS 204 ML-KEM"),
            None
        );
    }

    #[test]
    fn observed_briefing_standard_identifier_labels_capture_ir_publication_numbers() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let labels = observed_briefing_standard_identifier_labels(
            query,
            "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC",
        );

        assert_eq!(labels, vec!["IR 8413".to_string()]);
    }

    #[test]
    fn source_briefing_standard_identifier_labels_prefer_primary_publication_id_over_excerpt_reference(
    ) {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let labels = source_briefing_standard_identifier_labels(
            query,
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
            "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC",
            "IR 8413 documents NIST's third-round status report and notes that new public-key standards will augment Federal Information Processing Standard (FIPS) 186-4.",
        );

        assert_eq!(labels, BTreeSet::from(["IR 8413".to_string()]));
    }

    #[test]
    fn source_briefing_standard_identifier_labels_ignore_year_path_component_for_ir_publications() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let labels = source_briefing_standard_identifier_labels(
            query,
            "https://nvlpubs.nist.gov/nistpubs/ir/2022/NIST.IR.8413-upd1.pdf",
            "NIST IR 8413 Update 1 (PDF)",
            "NIST IR 8413 Update 1 summarizes the post-quantum cryptography standardization process.",
        );

        assert_eq!(labels, BTreeSet::from(["IR 8413".to_string()]));
    }

    #[test]
    fn source_document_authority_family_key_collapses_ir_update_variants() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let title =
            "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC";
        let excerpt =
            "The report references FIPS 203, FIPS 204, and FIPS 205 in the NIST post-quantum cryptography standardization process.";

        let original = source_document_authority_family_key(
            query,
            "https://csrc.nist.gov/pubs/ir/8413/final",
            title,
            excerpt,
        );
        let update = source_document_authority_family_key(
            query,
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
            title,
            excerpt,
        );

        assert_eq!(original, update);
    }

    #[test]
    fn source_document_authority_family_key_collapses_ir_update_variants_despite_excerpt_identifier_drift(
    ) {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let title =
            "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC";

        let original = source_document_authority_family_key(
            query,
            "https://csrc.nist.gov/pubs/ir/8413/final",
            title,
            "IR 8413 documents the third-round status of the NIST post-quantum cryptography standardization process.",
        );
        let update = source_document_authority_family_key(
            query,
            "https://csrc.nist.gov/pubs/ir/8413/upd1/final",
            title,
            "IR 8413 Update 1 summarizes the latest NIST post-quantum cryptography standards and references FIPS 203, FIPS 204, and FIPS 205.",
        );

        assert_eq!(original, update);
    }

    #[test]
    fn source_document_authority_family_key_distinguishes_distinct_fips_publications() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";
        let fips_203 = source_document_authority_family_key(
            query,
            "https://csrc.nist.gov/pubs/fips/203/final",
            "FIPS 203 Module-Lattice-Based Key-Encapsulation Mechanism Standard",
            "NIST finalized FIPS 203 as a post-quantum cryptography standard based on ML-KEM.",
        );
        let fips_204 = source_document_authority_family_key(
            query,
            "https://csrc.nist.gov/pubs/fips/204/final",
            "FIPS 204 Module-Lattice-Based Digital Signature Standard",
            "NIST finalized FIPS 204 as a post-quantum cryptography standard based on ML-DSA.",
        );

        assert_ne!(fips_203, fips_204);
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
    fn grounded_primary_authority_accepts_on_subject_official_standards_pages() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";

        assert!(source_has_grounded_primary_authority(
            query,
            "https://www.nist.gov/pqc",
            "Post-quantum cryptography | NIST",
            "NIST is advancing post-quantum cryptography standardization and transition guidance."
        ));
        assert!(source_has_grounded_primary_authority(
            query,
            "https://www.nist.gov/news-events/news/2024/08/nist-releases-first-3-finalized-post-quantum-encryption-standards",
            "NIST Releases First 3 Finalized Post-Quantum Encryption Standards | NIST",
            "August 13, 2024 - The finalized standards are FIPS 203, FIPS 204, and FIPS 205 for post-quantum cryptography."
        ));
    }

    #[test]
    fn grounded_primary_authority_rejects_generic_official_authority_neighbors() {
        let query =
            "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing.";

        assert!(!source_has_grounded_primary_authority(
            query,
            "https://www.nist.gov/cybersecurity-and-privacy",
            "Cybersecurity and Privacy | NIST",
            "NIST advances measurement science, standards, and technology for cybersecurity and privacy."
        ));
    }

    #[test]
    fn primary_authority_accepts_live_openai_pricing_surface_with_title_only() {
        let query = "What is the latest OpenAI API pricing?";
        let url = "https://openai.com/api/pricing/";
        let title = "OpenAI API Pricing | OpenAI";

        assert!(
            source_has_document_authority(query, url, title, ""),
            "official branded pricing page should retain document authority from host/title grounding"
        );
        assert!(
            source_counts_as_primary_authority(query, url, title, ""),
            "host-anchored current pricing query should count the official branded pricing page as primary authority"
        );
    }

    #[test]
    fn primary_authority_accepts_live_openai_pricing_surface_with_search_snippet() {
        let query = "What is the latest OpenAI API pricing?";
        let url = "https://openai.com/api/pricing/";
        let title = "OpenAI API Pricing | OpenAI";
        let excerpt = "Explore OpenAI API pricing for GPT-5.4, multimodal models, and tools. Compare token costs, realtime, image, and video pricing, plus service tiers.";

        assert!(source_has_document_authority(query, url, title, excerpt));
        assert!(source_counts_as_primary_authority(
            query, url, title, excerpt
        ));
    }

    #[test]
    fn host_anchored_primary_authority_snapshot_alignment_accepts_official_pricing_rate_card() {
        let query = "What is the latest OpenAI API pricing?";
        let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
            .expect("retrieval contract");
        let url = "https://openai.com/api/pricing/";
        let title = "OpenAI API Pricing | OpenAI";
        let excerpt = "Image: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs";

        assert!(query_requires_host_anchored_primary_authority(query));
        assert!(retrieval_contract_requires_primary_authority_source(
            Some(&retrieval_contract),
            query,
        ));
        assert!(source_counts_as_primary_authority(
            query, url, title, excerpt
        ));
        assert!(
            candidate_time_sensitive_resolvable_payload(url, title, excerpt),
            "title+excerpt should qualify as a resolvable current pricing payload"
        );
        assert!(
            source_has_host_anchored_primary_authority_snapshot_alignment(
                Some(&retrieval_contract),
                query,
                1,
                url,
                title,
                excerpt,
            )
        );
    }

    #[test]
    fn prioritized_query_grounding_excerpt_prefers_metric_surface_for_current_pricing_pages() {
        let query = "What is the latest OpenAI API pricing?";
        let url = "https://openai.com/api/pricing/";
        let title = "OpenAI API Pricing | OpenAI";
        let content = "Our frontier models are designed to spend more time thinking before producing a response, making them ideal for complex, multi-step problems.\n\nPricing above reflects standard processing rates for context lengths under 270K.\n\nNow: 1 GB for $0.03 / 64GB for $1.92 per container Starting March 31, 2026: 1 GB for $0.03 / 64GB for $1.92 per 20-minute session pass.\n\nAudio: $32.00 for inputs $0.40 for cached inputs $64.00 for outputs Text: $4.00 for inputs $0.40 for cached inputs $16.00 for outputs Image: $5.00 for inputs $0.50 for cached inputs\n\nState-of-the-art image generation model.\n\nImage: $8.00 for inputs $2.00 for cached inputs $32.00 for outputs Text: $5.00 for inputs $1.25 for cached inputs $10.00 for outputs";
        let retrieval_contract = crate::agentic::web::derive_web_retrieval_contract(query, None)
            .expect("retrieval contract");

        let selected = prioritized_query_grounding_excerpt_with_contract(
            Some(&retrieval_contract),
            query,
            1,
            url,
            title,
            content,
            240,
        );

        assert!(
            selected.contains("$32.00") || selected.contains("$8.00"),
            "selected={selected}"
        );
        assert!(
            contains_current_condition_metric_signal(&selected),
            "selected={selected}"
        );
        assert!(
            !selected.starts_with("Our frontier models are designed"),
            "selected={selected}"
        );
        assert!(
            !selected.contains("1 GB for $0.03") && !selected.contains("per container"),
            "selected={selected}"
        );
    }

    #[test]
    fn document_briefing_authority_alignment_accepts_empty_snippet_identifier_pages() {
        let query = "Research the latest NIST post-quantum cryptography standards and write me a one-page briefing using current web and local memory evidence, then return a cited brief with findings, uncertainties, and next checks.";
        let contract = crate::agentic::web::derive_web_retrieval_contract(query, Some(query))
            .expect("retrieval contract");
        let url = "https://csrc.nist.gov/pubs/ir/8413/final";
        let title =
            "IR 8413, Status Report on the Third Round of the NIST Post-Quantum Cryptography Standardization Process | CSRC";
        let excerpt = "";

        assert!(source_has_public_authority_host(url));
        assert!(source_has_briefing_standard_identifier_signal(
            query, url, title, excerpt
        ));
        assert!(query_prefers_document_briefing_layout(query));
        assert!(analyze_query_facets(query).grounded_external_required);
        assert!(
            query_native_anchor_tokens(query)
                .intersection(&source_anchor_tokens(url, title, excerpt))
                .count()
                >= 2
        );

        assert!(
            source_has_document_briefing_authority_alignment_with_contract(
                Some(&contract),
                query,
                2,
                url,
                title,
                excerpt,
            )
        );
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
