use super::*;

pub(crate) fn synthesis_query_contract(pending: &PendingSearchCompletion) -> String {
    let contract = pending.query_contract.trim();
    if !contract.is_empty() {
        return contract.to_string();
    }
    pending.query.trim().to_string()
}

pub(crate) fn fallback_search_summary(query: &str, url: &str) -> String {
    format!(
        "Searched '{}' at {}, but structured extraction failed. Retry refinement if needed.",
        query, url
    )
}

pub(crate) fn strip_markup(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut in_tag = false;
    for ch in input.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                out.push(' ');
            }
            _ if in_tag => {}
            _ => out.push(ch),
        }
    }
    out
}

pub(crate) fn compact_whitespace(input: &str) -> String {
    input.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn extract_urls(input: &str, limit: usize) -> Vec<String> {
    let mut urls = Vec::new();
    for raw in input.split_whitespace() {
        let trimmed = raw
            .trim_matches(|ch: char| ",.;:!?)]}\"'".contains(ch))
            .trim();
        if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
            continue;
        }
        if urls.iter().any(|existing| existing == trimmed) {
            continue;
        }
        urls.push(trimmed.to_string());
        if urls.len() >= limit {
            break;
        }
    }
    urls
}

pub(crate) fn extract_finding_lines(input: &str, limit: usize) -> Vec<String> {
    let mut findings = Vec::new();
    for line in input.lines() {
        let normalized = compact_whitespace(line).trim().to_string();
        if normalized.len() < 24 || normalized.len() > 200 {
            continue;
        }
        if normalized.starts_with("http://") || normalized.starts_with("https://") {
            continue;
        }
        if normalized.to_ascii_lowercase().contains("cookie")
            || normalized.to_ascii_lowercase().contains("javascript")
        {
            continue;
        }
        if findings.iter().any(|existing| existing == &normalized) {
            continue;
        }
        findings.push(normalized);
        if findings.len() >= limit {
            break;
        }
    }
    findings
}

pub(crate) fn summarize_search_results(query: &str, url: &str, extract_text: &str) -> String {
    let capped = extract_text
        .chars()
        .take(MAX_SEARCH_EXTRACT_CHARS)
        .collect::<String>();
    let stripped = strip_markup(&capped);
    let findings = extract_finding_lines(&stripped, 3);
    let urls = extract_urls(&capped, 2);

    let mut bullets: Vec<String> = Vec::new();
    for finding in findings {
        bullets.push(finding);
        if bullets.len() >= 3 {
            break;
        }
    }
    for link in urls.iter() {
        if bullets.len() >= 3 {
            break;
        }
        bullets.push(format!("Top link: {}", link));
    }

    if bullets.is_empty() {
        let snippet = compact_whitespace(&stripped)
            .chars()
            .take(180)
            .collect::<String>();
        if snippet.is_empty() {
            bullets.push("No high-signal snippets were extracted.".to_string());
        } else {
            bullets.push(format!("Extracted snippet: {}", snippet));
        }
    }

    let refinement_hint = if let Some(link) = urls.first() {
        format!(
            "Open '{}' or refine with more specific keywords (site:, date range, exact phrase).",
            link
        )
    } else {
        "Refine with more specific keywords (site:, date range, exact phrase).".to_string()
    };

    let mut summary = format!("Search summary for '{}':\n", query);
    for bullet in bullets.into_iter().take(3) {
        summary.push_str(&format!("- {}\n", bullet));
    }
    summary.push_str(&format!("- Source URL: {}\n", url));
    summary.push_str(&format!("Next refinement: {}", refinement_hint));
    summary
}
