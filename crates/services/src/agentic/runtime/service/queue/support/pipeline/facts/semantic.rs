use super::*;

pub(super) fn rendered_summary_semantic_floor_met(
    pending: &PendingSearchCompletion,
    rendered_summary: &str,
) -> bool {
    let query_contract = synthesis_query_contract(pending);
    if !query_requires_market_quote_grounding(&query_contract) {
        return true;
    }
    let query_lower = query_contract.to_ascii_lowercase();
    if !["investment", "invest", "better", "price", "market cap"]
        .iter()
        .any(|marker| query_lower.contains(marker))
    {
        return true;
    }

    let rendered_lower = rendered_summary.to_ascii_lowercase();
    let required_metric_groups = if query_requests_comparison(&query_contract) {
        2
    } else {
        1
    };

    let market_cap_markers = market_quote_market_cap_markers(pending, &query_contract);
    if market_cap_markers.len() < required_metric_groups
        || market_quote_metric_marker_groups_represented(&market_cap_markers, &rendered_lower)
            < required_metric_groups
    {
        return false;
    }

    let volume_markers = market_quote_volume_markers(pending, &query_contract);
    if volume_markers.len() < required_metric_groups
        || market_quote_metric_marker_groups_represented(&volume_markers, &rendered_lower)
            < required_metric_groups
    {
        return false;
    }

    true
}

fn market_quote_market_cap_markers(
    pending: &PendingSearchCompletion,
    query_contract: &str,
) -> Vec<Vec<String>> {
    pending
        .successful_reads
        .iter()
        .filter(|source| market_quote_source_is_quote_grade(source, query_contract))
        .filter_map(|source| market_quote_metric_marker_set(&source.excerpt, "market cap:"))
        .collect()
}

fn market_quote_volume_markers(
    pending: &PendingSearchCompletion,
    query_contract: &str,
) -> Vec<Vec<String>> {
    pending
        .successful_reads
        .iter()
        .filter(|source| market_quote_source_is_quote_grade(source, query_contract))
        .filter_map(|source| market_quote_metric_marker_set(&source.excerpt, "24h trading volume:"))
        .collect()
}

fn market_quote_metric_marker_groups_represented(
    marker_groups: &[Vec<String>],
    rendered_lower: &str,
) -> usize {
    if marker_groups.len() < 2 {
        return marker_groups.len();
    }
    marker_groups
        .iter()
        .filter(|markers| {
            markers
                .iter()
                .any(|marker| rendered_lower.contains(marker.as_str()))
        })
        .count()
}

fn market_quote_metric_marker_set(text: &str, label: &str) -> Option<Vec<String>> {
    let lower = text.to_ascii_lowercase();
    let start = lower.find(label)?;
    let after_label = &lower[start + label.len()..];
    let dollar = after_label.find('$')?;
    let after_dollar = &after_label[dollar + 1..];
    let number = after_dollar
        .chars()
        .take_while(|ch| ch.is_ascii_digit() || *ch == '.' || *ch == ',')
        .collect::<String>()
        .replace(',', "");
    let unit_tail = &after_dollar[after_dollar
        .find(|ch: char| !(ch.is_ascii_digit() || ch == '.' || ch == ','))
        .unwrap_or(after_dollar.len())..];
    let value = number.parse::<f64>().ok()?;
    if !value.is_finite() || value <= 0.0 {
        return None;
    }
    let unit = unit_tail.trim_start().chars().next().unwrap_or('m');
    if unit == 'b' {
        let whole_billions = value.floor() as u64;
        let one_decimal = format!("{value:.1}");
        let two_decimal = format!("{value:.2}");
        let whole_millions = (value * 1000.0).round() as u64;
        let mut markers = vec![
            format!("${two_decimal}b"),
            format!("${one_decimal}b"),
            format!("${whole_billions}b"),
            format!("${two_decimal} billion"),
            format!("${one_decimal} billion"),
            format!("${two_decimal}bn"),
            format!("${one_decimal}bn"),
            format!("${whole_millions}m"),
            format!("${whole_millions} million"),
        ];
        markers.dedup();
        return Some(markers);
    }
    let whole = value.floor() as u64;
    if whole == 0 {
        return None;
    }
    let rounded = value.round() as u64;
    let one_decimal = format!("{value:.1}");
    let two_decimal = format!("{value:.2}");
    let mut markers = vec![
        format!("${two_decimal}m"),
        format!("${one_decimal}m"),
        format!("${whole}m"),
        format!("${two_decimal} m"),
        format!("${one_decimal} m"),
        format!("${whole} m"),
        format!("${two_decimal} million"),
        format!("${one_decimal} million"),
        format!("${whole} million"),
        format!("${whole}."),
    ];
    if rounded != whole {
        markers.push(format!("${rounded}m"));
        markers.push(format!("${rounded} m"));
        markers.push(format!("${rounded} million"));
        markers.push(format!("${rounded}."));
    }
    markers.sort();
    markers.dedup();
    Some(markers)
}
