// Path: crates/services/src/agentic/desktop/execution/filesystem.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;
use std::fs;
use std::ops::Range;
use std::path::Path;

fn normalize_line(line: &str) -> String {
    line.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn source_line_ranges(source: &str) -> Vec<Range<usize>> {
    let bytes = source.as_bytes();
    let mut ranges = Vec::new();
    let mut line_start = 0;

    for (idx, byte) in bytes.iter().enumerate() {
        if *byte == b'\n' {
            let mut line_end = idx;
            if line_end > line_start && bytes[line_end - 1] == b'\r' {
                line_end -= 1;
            }
            ranges.push(line_start..line_end);
            line_start = idx + 1;
        }
    }

    if line_start < source.len() {
        ranges.push(line_start..source.len());
    }

    ranges
}

fn fuzzy_find_indices(source: &str, search: &str) -> Result<Range<usize>, String> {
    let source_ranges = source_line_ranges(source);
    let search_lines: Vec<_> = search.lines().map(normalize_line).collect();

    if search_lines.is_empty() {
        return Err("search block must contain at least one line".to_string());
    }

    if search_lines.len() > source_ranges.len() {
        return Err("search block not found in file".to_string());
    }

    let source_lines: Vec<_> = source_ranges
        .iter()
        .map(|range| normalize_line(&source[range.clone()]))
        .collect();

    let mut found_start = None;
    let window_size = search_lines.len();
    for start in 0..=source_lines.len() - window_size {
        if source_lines[start..start + window_size] == search_lines {
            if found_start.replace(start).is_some() {
                return Err(
                    "search block is ambiguous: found multiple fuzzy matches; provide more context"
                        .to_string(),
                );
            }
        }
    }

    let start = found_start.ok_or_else(|| "search block not found in file".to_string())?;
    let end = start + window_size - 1;
    Ok(source_ranges[start].start..source_ranges[end].end)
}

pub fn edit_line_content(
    original: &str,
    line_number: u32,
    replacement: &str,
) -> Result<String, String> {
    if line_number == 0 {
        return Err("line_number must be >= 1".to_string());
    }

    let mut lines: Vec<&str> = original.lines().collect();
    if lines.is_empty() {
        return Err("cannot edit line in empty file".to_string());
    }

    let index = (line_number - 1) as usize;
    if index >= lines.len() {
        return Err(format!(
            "line {} is out of range (file has {} line(s))",
            line_number,
            lines.len()
        ));
    }

    lines[index] = replacement;

    let newline = if original.contains("\r\n") {
        "\r\n"
    } else {
        "\n"
    };
    let mut updated = lines.join(newline);
    if original.ends_with('\n') {
        updated.push_str(newline);
    }

    Ok(updated)
}

fn apply_patch(original: &str, search: &str, replace: &str) -> Result<String, String> {
    if search.is_empty() {
        return Err("search block must be non-empty".to_string());
    }

    let mut exact_matches = original.match_indices(search);
    let range = match exact_matches.next() {
        Some((start, _)) => {
            if exact_matches.next().is_some() {
                return Err(
                    "search block is ambiguous: found multiple exact matches; provide more context"
                        .to_string(),
                );
            }
            start..start + search.len()
        }
        None => fuzzy_find_indices(original, search)?,
    };

    let mut new_content = String::with_capacity(original.len() + replace.len());
    new_content.push_str(&original[..range.start]);
    new_content.push_str(replace);
    new_content.push_str(&original[range.end..]);
    Ok(new_content)
}

#[cfg(test)]
mod tests {
    use super::{apply_patch, fuzzy_find_indices};

    #[test]
    fn fuzzy_patch_handles_indentation_mismatch() {
        let original = "def hello():\n    print(\"Hello\")\n    return True\n";
        let search = "  print(\"Hello\")\n  return True";
        let replace = "    print(\"World\")\n    return False";

        let updated = apply_patch(original, search, replace).expect("fuzzy patch should succeed");
        assert!(updated.contains("print(\"World\")"));
        assert!(updated.contains("return False"));
    }

    #[test]
    fn fuzzy_match_reports_ambiguity() {
        let source = "key = 1\nkey =  1\n";
        let search = "key = 1";
        let err = fuzzy_find_indices(source, search).expect_err("fuzzy match should be ambiguous");
        assert!(err.contains("ambiguous"));
    }
}

pub async fn handle(_exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
    match tool {
        AgentTool::FsRead { path } => match fs::read_to_string(&path) {
            Ok(content) => ToolExecutionResult::success(content),
            Err(e) => ToolExecutionResult::failure(format!("Failed to read {}: {}", path, e)),
        },
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            if let Some(line_number) = line_number {
                let existing = match fs::read_to_string(&path) {
                    Ok(content) => content,
                    Err(e) => {
                        return ToolExecutionResult::failure(format!(
                            "Failed to edit line {} in {}: {}",
                            line_number, path, e
                        ));
                    }
                };

                let updated = match edit_line_content(&existing, line_number, &content) {
                    Ok(updated) => updated,
                    Err(e) => {
                        return ToolExecutionResult::failure(format!(
                            "Failed to edit line {} in {}: {}",
                            line_number, path, e
                        ));
                    }
                };

                return match fs::write(&path, updated) {
                    Ok(_) => ToolExecutionResult::success(format!(
                        "Edited line {} in {}",
                        line_number, path
                    )),
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Failed to edit line {} in {}: {}",
                        line_number, path, e
                    )),
                };
            }

            if let Some(parent) = Path::new(&path).parent() {
                if !parent.exists() {
                    let _ = fs::create_dir_all(parent);
                }
            }
            match fs::write(&path, content) {
                Ok(_) => ToolExecutionResult::success(format!("Wrote to {}", path)),
                Err(e) => ToolExecutionResult::failure(format!("Failed to write {}: {}", path, e)),
            }
        }
        AgentTool::FsPatch {
            path,
            search,
            replace,
        } => {
            let existing = match fs::read_to_string(&path) {
                Ok(content) => content,
                Err(e) => {
                    return ToolExecutionResult::failure(format!("Failed to read {}: {}", path, e));
                }
            };

            let updated = match apply_patch(&existing, &search, &replace) {
                Ok(updated) => updated,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Patch failed for {}: {}",
                        path, e
                    ));
                }
            };

            match fs::write(&path, updated) {
                Ok(_) => ToolExecutionResult::success(format!("Patched {}", path)),
                Err(e) => ToolExecutionResult::failure(format!(
                    "Failed to write patch to {}: {}",
                    path, e
                )),
            }
        }
        AgentTool::FsList { path } => match fs::read_dir(&path) {
            Ok(entries) => {
                let mut list = Vec::new();
                for entry in entries.flatten() {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    let type_char = if entry.path().is_dir() { "D" } else { "F" };
                    list.push(format!("[{}] {}", type_char, name));
                }
                ToolExecutionResult::success(list.join("\n"))
            }
            Err(e) => ToolExecutionResult::failure(format!("Failed to list {}: {}", path, e)),
        },
        _ => ToolExecutionResult::failure("Unsupported FS action"),
    }
}
