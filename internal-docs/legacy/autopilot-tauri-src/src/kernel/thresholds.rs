use std::cmp::min;

pub const EXPANDED_MAX_LINES: usize = 80;
pub const EXPANDED_MAX_CHARS: usize = 8_000;
pub const COMMAND_OUTPUT_SPILL_LINES: usize = 200;
pub const DIFF_SPILL_TOTAL_LINES: usize = 300;
pub const DIFF_SPILL_FILES: usize = 3;
pub const EDIT_EXCERPT_MAX_LINES: usize = 20;

pub fn line_count(text: &str) -> usize {
    if text.is_empty() {
        0
    } else {
        text.lines().count()
    }
}

pub fn should_spill_command_output(output: &str) -> bool {
    line_count(output) > COMMAND_OUTPUT_SPILL_LINES
}

pub fn should_spill_diff(total_line_changes: usize, files_touched: usize) -> bool {
    total_line_changes > DIFF_SPILL_TOTAL_LINES || files_touched > DIFF_SPILL_FILES
}

pub fn trim_for_expanded_view(text: &str) -> String {
    trim_excerpt(text, EXPANDED_MAX_LINES, EXPANDED_MAX_CHARS)
}

pub fn trim_edit_excerpt(text: &str) -> String {
    trim_excerpt(text, EDIT_EXCERPT_MAX_LINES, EXPANDED_MAX_CHARS)
}

pub fn trim_excerpt(text: &str, max_lines: usize, max_chars: usize) -> String {
    if text.is_empty() || max_lines == 0 || max_chars == 0 {
        return String::new();
    }

    let mut out = text.lines().take(max_lines).collect::<Vec<_>>().join("\n");

    if out.chars().count() > max_chars {
        let mut clipped = String::new();
        let take = min(max_chars, out.chars().count());
        for ch in out.chars().take(take) {
            clipped.push(ch);
        }
        clipped.push_str("\n…");
        out = clipped;
    } else if line_count(text) > max_lines {
        out.push_str("\n…");
    }

    out
}

pub fn estimate_diff_stats(diff_text: &str) -> (usize, usize) {
    if diff_text.trim().is_empty() {
        return (0, 0);
    }

    let mut files_touched = 0usize;
    let mut line_changes = 0usize;

    for line in diff_text.lines() {
        if line.starts_with("diff --git ") {
            files_touched += 1;
            continue;
        }

        // Count only real add/remove diff lines; ignore headers.
        if (line.starts_with('+') && !line.starts_with("+++ "))
            || (line.starts_with('-') && !line.starts_with("--- "))
        {
            line_changes += 1;
        }
    }

    // Fallback for compact summaries that lack "diff --git" headers.
    if files_touched == 0 && line_changes > 0 {
        files_touched = 1;
    }

    (line_changes, files_touched)
}

#[cfg(test)]
#[path = "thresholds/tests.rs"]
mod tests;
