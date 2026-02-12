// Path: crates/services/src/agentic/desktop/execution/filesystem.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;
use regex::Regex;
use std::fs;
use std::io::{BufRead, BufReader};
use std::ops::Range;
use std::path::Path;
use walkdir::{DirEntry, WalkDir};

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

const MAX_SEARCH_MATCHES: usize = 50;
const MAX_SEARCH_FILE_BYTES: u64 = 1_000_000;
const SEARCH_EXCLUDED_DIRS: [&str; 3] = [".git", "node_modules", "target"];

fn wildcard_match(pattern: &str, candidate: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let c: Vec<char> = candidate.chars().collect();
    let mut dp = vec![vec![false; c.len() + 1]; p.len() + 1];
    dp[0][0] = true;

    for i in 1..=p.len() {
        if p[i - 1] == '*' {
            dp[i][0] = dp[i - 1][0];
        }
    }

    for i in 1..=p.len() {
        for j in 1..=c.len() {
            dp[i][j] = match p[i - 1] {
                '*' => dp[i - 1][j] || dp[i][j - 1],
                '?' => dp[i - 1][j - 1],
                ch => dp[i - 1][j - 1] && ch == c[j - 1],
            };
        }
    }

    dp[p.len()][c.len()]
}

fn matches_file_pattern(path: &Path, pattern: &str) -> bool {
    if pattern.trim().is_empty() {
        return true;
    }

    let file_name = path
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or_default();
    wildcard_match(pattern, file_name) || wildcard_match(pattern, &path.to_string_lossy())
}

fn is_excluded_dir(entry: &DirEntry) -> bool {
    entry.file_type().is_dir()
        && SEARCH_EXCLUDED_DIRS
            .iter()
            .any(|name| entry.file_name().to_string_lossy() == *name)
}

fn search_files(
    root: &str,
    regex_pattern: &str,
    file_filter: Option<&str>,
) -> Result<String, String> {
    let root_path = Path::new(root);
    if !root_path.exists() {
        return Err(format!("Path does not exist: {}", root));
    }
    if !root_path.is_dir() {
        return Err(format!("Path is not a directory: {}", root));
    }

    let line_re = Regex::new(regex_pattern).map_err(|e| format!("Invalid regex: {}", e))?;
    let mut matches = Vec::new();
    let mut total_matches = 0usize;

    let walker = WalkDir::new(root_path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|entry| !is_excluded_dir(entry));

    for entry in walker {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => continue,
        };

        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();

        if let Some(pattern) = file_filter {
            if !matches_file_pattern(path, pattern) {
                continue;
            }
        }

        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(_) => continue,
        };
        if metadata.len() > MAX_SEARCH_FILE_BYTES {
            continue;
        }

        let file = match fs::File::open(path) {
            Ok(file) => file,
            Err(_) => continue,
        };
        let reader = BufReader::new(file);

        for (line_idx, line_result) in reader.lines().enumerate() {
            let line = match line_result {
                Ok(line) => line,
                Err(_) => break,
            };

            if line_re.is_match(&line) {
                matches.push(format!(
                    "{}:{}: {}",
                    path.display(),
                    line_idx + 1,
                    line.trim()
                ));
                total_matches += 1;
                if total_matches >= MAX_SEARCH_MATCHES {
                    matches.push("... [truncated: too many matches] ...".to_string());
                    return Ok(matches.join("\n"));
                }
            }
        }
    }

    if matches.is_empty() {
        Ok("No matches found.".to_string())
    } else {
        Ok(matches.join("\n"))
    }
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
        AgentTool::FsSearch {
            path,
            regex,
            file_pattern,
        } => {
            let task = tokio::task::spawn_blocking(move || {
                search_files(&path, &regex, file_pattern.as_deref())
            })
            .await;

            match task {
                Ok(Ok(output)) => ToolExecutionResult::success(output),
                Ok(Err(e)) => ToolExecutionResult::failure(format!("Search failed: {}", e)),
                Err(e) => ToolExecutionResult::failure(format!("Search task panicked: {}", e)),
            }
        }
        _ => ToolExecutionResult::failure("Unsupported FS action"),
    }
}
