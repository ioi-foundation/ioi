use super::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CanonicalIdentifierGroup {
    pub(crate) key: &'static str,
    pub(crate) primary_label: &'static str,
    pub(crate) required: bool,
    pub(crate) needles: &'static [&'static str],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EvidenceIdentifierObservation {
    pub(crate) url: String,
    pub(crate) surface: String,
    pub(crate) authoritative: bool,
}

pub(crate) fn evidence_standard_identifier_groups_for_query(
    _query_contract: &str,
) -> &'static [CanonicalIdentifierGroup] {
    // Subject-specific identifier expansion is intentionally disabled until it can be
    // derived from generic discovery signals rather than query-class heuristics.
    &[]
}

pub(crate) fn evidence_standard_identifier_group_floor(query_contract: &str) -> usize {
    evidence_standard_identifier_groups_for_query(query_contract)
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

fn is_standard_fips_number(token: &str) -> bool {
    token.len() == 3 && token.chars().all(|ch| ch.is_ascii_digit())
}

fn is_standard_ir_number(token: &str) -> bool {
    (3..=5).contains(&token.len()) && token.chars().all(|ch| ch.is_ascii_digit())
}

fn parse_standard_ir_number(token: &str) -> Option<usize> {
    is_standard_ir_number(token)
        .then(|| token.parse::<usize>().ok())
        .flatten()
}

fn is_year_like_ir_directory(number: usize) -> bool {
    (2000..=2100).contains(&number)
}

fn evidence_identifier_sort_key(label: &str) -> (usize, usize, String) {
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

fn sort_evidence_identifier_labels<I>(labels: I) -> Vec<String>
where
    I: IntoIterator<Item = String>,
{
    let mut ordered = labels.into_iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| {
        evidence_identifier_sort_key(left).cmp(&evidence_identifier_sort_key(right))
    });
    ordered
}

fn observed_generic_evidence_standard_identifier_labels(surface: &str) -> Vec<String> {
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
                if let Some(number) = parse_standard_ir_number(token) {
                    if is_year_like_ir_directory(number) {
                        let mut recovered = None;
                        let lookahead_end = idx.saturating_add(6).min(tokens.len());
                        let mut cursor = idx + 2;
                        while cursor + 1 < lookahead_end {
                            if tokens[cursor] == "ir" {
                                if let Some(next_token) = tokens.get(cursor + 1).copied() {
                                    if let Some(next_number) = parse_standard_ir_number(next_token)
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

        let Some(token) = tokens.get(idx + 1).copied() else {
            idx += 1;
            continue;
        };
        if !is_standard_fips_number(token) {
            idx += 1;
            continue;
        }

        let mut cursor = idx + 2;
        let mut shorthand_or_revision = false;
        while cursor < tokens.len() {
            let token = tokens[cursor];
            if token == "fips" {
                break;
            }
            if is_standard_fips_number(token) || token.chars().all(|ch| ch.is_ascii_digit()) {
                shorthand_or_revision = true;
                break;
            }
            if matches!(token, "and" | "or" | "plus") {
                cursor += 1;
                continue;
            }
            break;
        }

        if !shorthand_or_revision {
            labels.insert(format!("FIPS {}", token));
            idx += 2;
            continue;
        }
        idx += 1;
    }

    sort_evidence_identifier_labels(labels)
}

fn observed_compressed_fips_identifier_labels(query_contract: &str, surface: &str) -> Vec<String> {
    if !query_prefers_document_report_layout(query_contract)
        || query_requests_comparison(query_contract)
    {
        return Vec::new();
    }
    let lower = surface.to_ascii_lowercase();
    if !(lower.contains("post-quantum")
        || lower.contains("post quantum")
        || lower.contains("postquantum")
        || lower.contains("quantum"))
    {
        return Vec::new();
    }

    let normalized = normalized_identifier_surface(surface);
    if normalized.is_empty() {
        return Vec::new();
    }
    let tokens = normalized.split_whitespace().collect::<Vec<_>>();
    let mut labels = BTreeSet::new();
    let mut idx = 0usize;
    while idx + 1 < tokens.len() {
        if tokens[idx] != "fips" || !is_standard_fips_number(tokens[idx + 1]) {
            idx += 1;
            continue;
        }

        let mut numbers = vec![tokens[idx + 1]];
        let mut cursor = idx + 2;
        let lookahead_end = (idx + 10).min(tokens.len());
        while cursor < lookahead_end {
            let token = tokens[cursor];
            if token == "fips" {
                break;
            }
            if is_standard_fips_number(token) {
                numbers.push(token);
                cursor += 1;
                continue;
            }
            if token.chars().all(|ch| ch.is_ascii_digit()) {
                break;
            }
            if matches!(token, "and" | "or" | "plus") {
                cursor += 1;
                continue;
            }
            break;
        }

        if numbers.len() >= 2 {
            for number in numbers {
                labels.insert(format!("FIPS {}", number));
            }
            idx = cursor.max(idx + 2);
            continue;
        }
        idx += 1;
    }

    sort_evidence_identifier_labels(labels)
}

pub(crate) fn observed_evidence_standard_identifier_labels_with_compressed_fips(
    query_contract: &str,
    surface: &str,
) -> Vec<String> {
    let mut labels = observed_evidence_standard_identifier_labels(query_contract, surface)
        .into_iter()
        .collect::<BTreeSet<_>>();
    labels.extend(observed_compressed_fips_identifier_labels(
        query_contract,
        surface,
    ));
    sort_evidence_identifier_labels(labels)
}

pub(crate) fn observed_evidence_standard_identifier_groups(
    query_contract: &str,
    surface: &str,
) -> Vec<CanonicalIdentifierGroup> {
    let normalized_surface = normalized_identifier_surface(surface);
    if normalized_surface.is_empty() {
        return Vec::new();
    }
    evidence_standard_identifier_groups_for_query(query_contract)
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

pub(crate) fn observed_evidence_standard_identifier_labels(
    query_contract: &str,
    surface: &str,
) -> Vec<String> {
    let static_labels = observed_evidence_standard_identifier_groups(query_contract, surface)
        .into_iter()
        .map(|group| group.primary_label.to_string())
        .collect::<BTreeSet<_>>();
    let generic_labels = observed_generic_evidence_standard_identifier_labels(surface)
        .into_iter()
        .collect::<BTreeSet<_>>();
    sort_evidence_identifier_labels(static_labels.into_iter().chain(generic_labels))
}

pub(crate) fn preferred_source_evidence_identifier_surface(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> String {
    let primary_surface = compact_whitespace(&format!("{url} {title}"));
    if !primary_surface.is_empty()
        && !observed_evidence_standard_identifier_labels(query_contract, &primary_surface)
            .is_empty()
    {
        return primary_surface;
    }

    compact_whitespace(&format!("{url} {title} {excerpt}"))
}

pub(crate) fn source_evidence_standard_identifier_labels(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> BTreeSet<String> {
    observed_evidence_standard_identifier_labels_with_compressed_fips(
        query_contract,
        &preferred_source_evidence_identifier_surface(query_contract, url, title, excerpt),
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

    let identifier_labels = sort_evidence_identifier_labels(
        source_evidence_standard_identifier_labels(query_contract, url, title, excerpt),
    );
    if !identifier_labels.is_empty() {
        return Some(format!(
            "evidence-identifier:{}",
            identifier_labels.join("|")
        ));
    }

    let surface_key = normalized_identifier_surface(&preferred_source_evidence_identifier_surface(
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

pub(crate) fn source_has_evidence_standard_identifier_signal(
    query_contract: &str,
    url: &str,
    title: &str,
    excerpt: &str,
) -> bool {
    !source_evidence_standard_identifier_labels(query_contract, url, title, excerpt).is_empty()
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

pub(super) fn prioritized_standard_identifier_excerpt(
    query_contract: &str,
    input: &str,
    max_chars: usize,
) -> String {
    let compact = compact_whitespace(input);
    if compact.is_empty() || looks_like_structured_metadata_noise(&compact) {
        return String::new();
    }
    if observed_evidence_standard_identifier_labels(query_contract, &compact).is_empty() {
        return prioritized_fips_shorthand_excerpt(query_contract, &compact, max_chars);
    }

    #[derive(Clone)]
    struct IdentifierSegment {
        text: String,
        required_labels: BTreeSet<String>,
        total_hits: usize,
        authority_marker_hits: usize,
    }

    let inferred_labels = observed_evidence_standard_identifier_labels(query_contract, &compact)
        .into_iter()
        .collect::<BTreeSet<_>>();
    let required_floor = inferred_labels.len();
    let mut segments = compact
        .split(['.', '!', '?', ';', '\n'])
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .filter_map(|segment| {
            let observed_labels =
                observed_evidence_standard_identifier_labels(query_contract, segment)
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
                total_hits: observed_evidence_standard_identifier_labels(query_contract, segment)
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
        let anchor = observed_evidence_standard_identifier_labels(query_contract, segment)
            .into_iter()
            .filter_map(|label| lower.find(&label.to_ascii_lowercase()))
            .min();
        let Some(anchor) = anchor else {
            return normalize_evidence_identifier_display_text(segment)
                .chars()
                .take(max_chars)
                .collect::<String>();
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
        normalize_evidence_identifier_display_text(segment[start..].trim())
            .chars()
            .take(max_chars)
            .collect()
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

pub(crate) fn preferred_evidence_identifier_alias(label: &str, surface: &str) -> Option<String> {
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

fn normalize_evidence_identifier_display_text(input: &str) -> String {
    compact_whitespace(input).replace("(FIPS) ", "FIPS ")
}

fn prioritized_fips_shorthand_excerpt(
    query_contract: &str,
    input: &str,
    max_chars: usize,
) -> String {
    if !query_prefers_document_report_layout(query_contract)
        || query_requests_comparison(query_contract)
    {
        return String::new();
    }
    let lower = input.to_ascii_lowercase();
    if !(lower.contains("post-quantum")
        || lower.contains("post quantum")
        || lower.contains("quantum"))
    {
        return String::new();
    }

    let normalized = normalized_identifier_surface(input);
    let tokens = normalized.split_whitespace().collect::<Vec<_>>();
    let mut has_shorthand = false;
    let mut idx = 0usize;
    while idx + 2 < tokens.len() {
        if tokens[idx] != "fips" || !is_standard_fips_number(tokens[idx + 1]) {
            idx += 1;
            continue;
        }
        let lookahead_end = (idx + 8).min(tokens.len());
        if tokens[idx + 2..lookahead_end]
            .iter()
            .any(|token| is_standard_fips_number(token))
        {
            has_shorthand = true;
            break;
        }
        idx += 1;
    }
    if !has_shorthand {
        return String::new();
    }

    let Some(anchor) = lower.find("fips") else {
        return String::new();
    };
    let start = input[..anchor]
        .rfind(|ch: char| matches!(ch, '.' | '!' | '?' | ';' | '\n'))
        .map(|idx| idx + 1)
        .unwrap_or(0);
    normalize_evidence_identifier_display_text(input[start..].trim())
        .chars()
        .take(max_chars)
        .collect()
}

pub(crate) fn infer_answer_required_identifier_labels(
    query_contract: &str,
    observations: &[EvidenceIdentifierObservation],
) -> BTreeSet<String> {
    if !query_prefers_document_report_layout(query_contract)
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
        let labels = observed_evidence_standard_identifier_labels_with_compressed_fips(
            query_contract,
            &observation.surface,
        )
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
                    sort_evidence_identifier_labels(right.iter().cloned())
                        .cmp(&sort_evidence_identifier_labels(left.iter().cloned()))
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

pub(crate) fn inferred_evidence_identifier_group_floor(
    query_contract: &str,
    observations: &[EvidenceIdentifierObservation],
) -> usize {
    infer_answer_required_identifier_labels(query_contract, observations).len()
}

pub(crate) fn preferred_evidence_identifier_display_labels(
    labels: impl IntoIterator<Item = String>,
    observations: &[EvidenceIdentifierObservation],
) -> Vec<String> {
    sort_evidence_identifier_labels(labels)
        .into_iter()
        .map(|label| {
            observations
                .iter()
                .filter_map(|observation| {
                    preferred_evidence_identifier_alias(&label, &observation.surface).map(|alias| {
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
