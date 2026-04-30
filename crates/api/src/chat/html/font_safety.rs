fn safe_font_family_fallback_for_declaration(declaration: &str) -> String {
    let normalized_segments = declaration
        .split(',')
        .map(|segment| segment.trim().trim_matches('\'').trim_matches('"'))
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.to_ascii_lowercase())
        .collect::<Vec<_>>();

    if normalized_segments.iter().any(|segment| {
        matches!(
            segment.as_str(),
            "ui-monospace" | "monospace" | "courier new"
        )
    }) {
        return " ui-monospace, monospace".to_string();
    }

    if normalized_segments.iter().any(|segment| {
        matches!(
            segment.as_str(),
            "serif" | "ui-serif" | "georgia" | "times new roman"
        )
    }) {
        return " ui-serif, serif".to_string();
    }

    " system-ui, sans-serif".to_string()
}

pub(super) fn html_uses_external_runtime_dependency(html_lower: &str) -> bool {
    if html_lower.contains("<script src=")
        || html_lower.contains("<script src='")
        || html_lower.contains("<link rel=")
        || html_lower.contains("<link rel='")
    {
        return true;
    }

    let d3_defined_locally = ["const d3", "let d3", "var d3", "function d3", "class d3"]
        .iter()
        .any(|needle| html_lower.contains(needle));
    if html_lower.contains("d3.") && !d3_defined_locally {
        return true;
    }

    let chart_defined_locally = [
        "const chart",
        "let chart",
        "var chart",
        "function chart",
        "class chart",
    ]
    .iter()
    .any(|needle| html_lower.contains(needle));
    html_lower.contains("new chart(") && !chart_defined_locally
}
