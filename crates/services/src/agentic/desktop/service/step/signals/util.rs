pub(crate) fn marker_hits(lower_text: &str, markers: &[&str]) -> usize {
    markers
        .iter()
        .filter(|marker| lower_text.contains(**marker))
        .count()
}

pub(crate) fn normalize_marker_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push(' ');
    let mut last_was_space = true;
    for ch in text.chars() {
        let lower = ch.to_ascii_lowercase();
        if lower.is_ascii_alphanumeric() {
            out.push(lower);
            last_was_space = false;
            continue;
        }
        if !last_was_space {
            out.push(' ');
            last_was_space = true;
        }
    }
    if !out.ends_with(' ') {
        out.push(' ');
    }
    out
}
