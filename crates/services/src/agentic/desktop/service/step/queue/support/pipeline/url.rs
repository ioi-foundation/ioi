use super::*;

pub(crate) fn normalized_url_path(path: &str) -> String {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/" {
        return "/".to_string();
    }
    let lowered = trimmed.to_ascii_lowercase();
    let stripped = lowered.trim_end_matches('/');
    if stripped.is_empty() {
        "/".to_string()
    } else {
        stripped.to_string()
    }
}

pub(crate) fn url_structural_key(url: &str) -> Option<UrlStructuralKey> {
    let parsed = Url::parse(url.trim()).ok()?;
    let host = parsed.host_str()?.trim().to_ascii_lowercase();
    if host.is_empty() {
        return None;
    }
    let path = normalized_url_path(parsed.path());
    let mut query_tokens = BTreeSet::new();
    if let Some(query) = parsed.query() {
        query_tokens.extend(normalized_locality_tokens(query));
        query_tokens.extend(normalized_anchor_tokens(query));
    }

    Some(UrlStructuralKey {
        host,
        path,
        query_tokens,
    })
}

pub(crate) fn normalized_url_literal(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    if let Some(key) = url_structural_key(trimmed) {
        let mut normalized = format!("{}{}", key.host, key.path);
        if !key.query_tokens.is_empty() {
            normalized.push('?');
            normalized.push_str(
                &key.query_tokens
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("&"),
            );
        }
        return normalized;
    }
    trimmed
        .trim_end_matches('/')
        .split_whitespace()
        .collect::<String>()
        .to_ascii_lowercase()
}

pub(crate) fn url_structural_query_overlap(
    left: &UrlStructuralKey,
    right: &UrlStructuralKey,
) -> usize {
    left.query_tokens.intersection(&right.query_tokens).count()
}

pub(crate) fn url_structurally_equivalent(left: &str, right: &str) -> bool {
    let left_trimmed = left.trim();
    let right_trimmed = right.trim();
    if left_trimmed.is_empty() || right_trimmed.is_empty() {
        return false;
    }
    if left_trimmed.eq_ignore_ascii_case(right_trimmed) {
        return true;
    }

    match (
        url_structural_key(left_trimmed),
        url_structural_key(right_trimmed),
    ) {
        (Some(left_key), Some(right_key)) => {
            if left_key.host != right_key.host || left_key.path != right_key.path {
                return false;
            }
            if left_key.query_tokens.is_empty() || right_key.query_tokens.is_empty() {
                return true;
            }
            url_structural_query_overlap(&left_key, &right_key) > 0
        }
        _ => normalized_url_literal(left_trimmed) == normalized_url_literal(right_trimmed),
    }
}

pub(crate) fn hint_for_url<'a>(
    pending: &'a PendingSearchCompletion,
    url: &str,
) -> Option<&'a PendingSearchReadSummary> {
    let trimmed = url.trim();
    if trimmed.is_empty() {
        return None;
    }
    if let Some(exact) = pending
        .candidate_source_hints
        .iter()
        .find(|hint| hint.url.trim().eq_ignore_ascii_case(trimmed))
    {
        return Some(exact);
    }

    let target_key = url_structural_key(trimmed)?;
    let mut best_hint: Option<&PendingSearchReadSummary> = None;
    let mut best_overlap = 0usize;
    for hint in &pending.candidate_source_hints {
        let hint_trimmed = hint.url.trim();
        if hint_trimmed.is_empty() {
            continue;
        }
        let Some(hint_key) = url_structural_key(hint_trimmed) else {
            continue;
        };
        if hint_key.host != target_key.host || hint_key.path != target_key.path {
            continue;
        }
        if !hint_key.query_tokens.is_empty()
            && !target_key.query_tokens.is_empty()
            && url_structural_query_overlap(&hint_key, &target_key) == 0
        {
            continue;
        }
        let overlap = url_structural_query_overlap(&hint_key, &target_key);
        let should_replace = best_hint.is_none() || overlap > best_overlap;
        if should_replace {
            best_overlap = overlap;
            best_hint = Some(hint);
        }
    }

    best_hint
}
