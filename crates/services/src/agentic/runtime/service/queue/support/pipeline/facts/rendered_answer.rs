use super::*;

pub(super) fn rendered_summary_line_is_legacy_source_cluster_header(line: &str) -> bool {
    line.trim()
        .to_ascii_lowercase()
        .strip_prefix("story ")
        .and_then(|rest| rest.split_once(':'))
        .is_some()
}

pub(super) fn rendered_summary_starts_structured_postamble(line: &str) -> bool {
    [
        "Citations:",
        "Blocked sources requiring human challenge:",
        "Partial evidence:",
        "Retrieval evidence:",
        "Completion reason:",
        "Run date (UTC):",
        "Run timestamp (UTC):",
        "Overall confidence:",
        "Overall caveat:",
        "Query:",
        "Insight selector:",
        "Insights used:",
        "Conflicts:",
        "Evidence gaps:",
    ]
    .iter()
    .any(|marker| line.eq_ignore_ascii_case(marker) || line.starts_with(marker))
}

pub(super) fn rendered_summary_starts_required_section(
    line: &str,
    required_sections: &[RequiredAnswerSection],
) -> bool {
    required_sections
        .iter()
        .any(|section| line.starts_with(format!("{}:", section.label.trim()).as_str()))
}

pub(in crate::agentic::runtime::service::queue::support::pipeline) fn rendered_summary_citation_urls(
    rendered_summary: &str,
    required_sections: &[RequiredAnswerSection],
) -> Vec<String> {
    let mut citation_urls = BTreeSet::new();
    let mut in_citation_block = false;

    for line in rendered_summary.lines() {
        let trimmed = line.trim();
        if trimmed.eq_ignore_ascii_case("Citations:")
            || trimmed.eq_ignore_ascii_case("Sources:")
            || trimmed.eq_ignore_ascii_case("Key sources:")
            || trimmed.eq_ignore_ascii_case("### Sources")
            || trimmed.eq_ignore_ascii_case("## Sources")
        {
            in_citation_block = true;
            continue;
        }
        if !in_citation_block {
            continue;
        }
        if trimmed.is_empty() {
            continue;
        }
        if rendered_summary_starts_structured_postamble(trimmed)
            || rendered_summary_line_is_legacy_source_cluster_header(trimmed)
            || trimmed.eq_ignore_ascii_case("Comparison:")
            || rendered_summary_starts_required_section(trimmed, required_sections)
        {
            in_citation_block = false;
            continue;
        }
        citation_urls.extend(extract_urls(trimmed, 8));
    }

    citation_urls.into_iter().collect()
}

pub(super) fn rendered_summary_section_blocks(
    rendered_summary: &str,
    required_sections: &[RequiredAnswerSection],
) -> BTreeMap<String, Vec<String>> {
    let mut sections = BTreeMap::<String, Vec<String>>::new();
    let prefixes = required_sections
        .iter()
        .map(|section| (section.key.clone(), format!("{}:", section.label.trim())))
        .collect::<Vec<_>>();
    let mut current_key = None::<String>;

    for line in rendered_summary.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if rendered_summary_starts_structured_postamble(trimmed) {
            current_key = None;
            continue;
        }
        if let Some((key, prefix)) = prefixes
            .iter()
            .find(|(_, prefix)| trimmed.starts_with(prefix.as_str()))
        {
            current_key = Some(key.clone());
            let remainder = trimmed[prefix.len()..].trim();
            if !remainder.is_empty() {
                sections
                    .entry(key.clone())
                    .or_default()
                    .push(compact_whitespace(remainder));
                current_key = None;
            }
            continue;
        }
        let Some(key) = current_key.clone() else {
            continue;
        };
        let block = if let Some(rest) = trimmed.strip_prefix("- ") {
            compact_whitespace(rest)
        } else {
            compact_whitespace(trimmed)
        };
        if block.is_empty() {
            continue;
        }
        sections.entry(key).or_default().push(block);
        if !trimmed.starts_with("- ") {
            current_key = None;
        }
    }

    sections
}

pub(super) fn rendered_summary_inventory_surface(blocks: &[String]) -> String {
    let Some(first_block) = blocks.first() else {
        return String::new();
    };
    let compact = compact_whitespace(first_block);
    if compact.is_empty() {
        return String::new();
    }
    if let Some((prefix, _)) = compact.split_once(" According to ") {
        return prefix.trim().to_string();
    }
    compact
}
