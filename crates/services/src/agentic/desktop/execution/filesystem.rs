// Path: crates/services/src/agentic/desktop/execution/filesystem.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;
use regex::Regex;
use std::env;
use std::fs;
use std::io::{BufRead, BufReader};
use std::ops::Range;
use std::path::{Path, PathBuf};
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

fn resolve_working_directory(cwd: Option<&str>) -> Result<PathBuf, String> {
    let normalized = cwd.unwrap_or(".").trim();
    let candidate = if normalized.is_empty() {
        PathBuf::from(".")
    } else {
        PathBuf::from(normalized)
    };

    let absolute = if candidate.is_absolute() {
        candidate
    } else {
        env::current_dir()
            .map_err(|e| format!("Failed to resolve current directory: {}", e))?
            .join(candidate)
    };

    if !absolute.exists() {
        return Err(format!(
            "Working directory '{}' does not exist.",
            absolute.display()
        ));
    }

    if !absolute.is_dir() {
        return Err(format!(
            "Working directory '{}' is not a directory.",
            absolute.display()
        ));
    }

    Ok(absolute)
}

fn resolve_tool_path(path: &str, cwd: Option<&str>) -> Result<PathBuf, String> {
    let trimmed = path.trim();
    if trimmed.is_empty() {
        return Err("Path cannot be empty.".to_string());
    }

    let requested = PathBuf::from(trimmed);
    if requested.is_absolute() {
        Ok(requested)
    } else {
        Ok(resolve_working_directory(cwd)?.join(requested))
    }
}

fn list_directory_entries(path: &Path) -> Result<Vec<(String, &'static str)>, String> {
    let entries =
        fs::read_dir(path).map_err(|e| format!("Failed to list {}: {}", path.display(), e))?;

    let mut list = Vec::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        let type_char = if entry.path().is_dir() { "D" } else { "F" };
        list.push((name, type_char));
    }

    // Deterministic output order prevents flaky tool responses across platforms/filesystems.
    list.sort_by(|(name_a, kind_a), (name_b, kind_b)| {
        name_a.cmp(name_b).then_with(|| kind_a.cmp(kind_b))
    });
    Ok(list)
}

fn search_files(
    root: &Path,
    regex_pattern: &str,
    file_filter: Option<&str>,
) -> Result<String, String> {
    if !root.exists() {
        return Err(format!("Path does not exist: {}", root.display()));
    }
    if !root.is_dir() {
        return Err(format!("Path is not a directory: {}", root.display()));
    }

    let line_re = Regex::new(regex_pattern).map_err(|e| format!("Invalid regex: {}", e))?;
    let mut matches = Vec::new();
    let mut total_matches = 0usize;

    let walker = WalkDir::new(root)
        .follow_links(false)
        .sort_by_file_name()
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
    use super::{
        apply_patch, fuzzy_find_indices, list_directory_entries, resolve_tool_path, search_files,
    };
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be after epoch")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ioi-services-fs-test-{}-{}-{}",
            name,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).expect("test temp directory should be created");
        dir
    }

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

    #[test]
    fn resolve_tool_path_uses_working_directory_for_relative_paths() {
        let cwd = std::env::current_dir().expect("current dir should resolve");
        let cwd_str = cwd.to_string_lossy().to_string();
        let resolved =
            resolve_tool_path("nested/file.txt", Some(&cwd_str)).expect("path should resolve");
        assert_eq!(resolved, cwd.join("nested/file.txt"));
    }

    #[test]
    fn resolve_tool_path_preserves_absolute_paths() {
        let cwd = std::env::current_dir().expect("current dir should resolve");
        let absolute = cwd.join("absolute.txt");
        let absolute_str = absolute.to_string_lossy().to_string();
        let resolved =
            resolve_tool_path(&absolute_str, Some(".")).expect("absolute path should pass");
        assert_eq!(resolved, absolute);
    }

    #[test]
    fn list_directory_entries_returns_sorted_output() {
        let dir = make_temp_dir("list-order");
        fs::write(dir.join("zeta.txt"), "z").expect("zeta file should be written");
        fs::write(dir.join("alpha.txt"), "a").expect("alpha file should be written");
        fs::create_dir_all(dir.join("beta")).expect("beta dir should be created");

        let listing = list_directory_entries(&dir).expect("listing should succeed");
        let rendered: Vec<String> = listing
            .into_iter()
            .map(|(name, kind)| format!("[{}] {}", kind, name))
            .collect();

        assert_eq!(rendered, vec!["[F] alpha.txt", "[D] beta", "[F] zeta.txt"]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn search_files_traversal_is_sorted_by_filename() {
        let dir = make_temp_dir("search-order");
        fs::write(dir.join("b.txt"), "needle in b").expect("b file should be written");
        fs::write(dir.join("a.txt"), "needle in a").expect("a file should be written");

        let output = search_files(&dir, "needle", Some("*.txt")).expect("search should succeed");
        let lines: Vec<&str> = output.lines().collect();

        assert_eq!(lines.len(), 2);
        assert!(lines[0].contains("a.txt:1: needle in a"));
        assert!(lines[1].contains("b.txt:1: needle in b"));

        let _ = fs::remove_dir_all(&dir);
    }
}

pub async fn handle(exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
    let cwd = exec.working_directory.as_deref();

    match tool {
        AgentTool::FsRead { path } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!("Failed to read {}: {}", path, e))
                }
            };

            match fs::read_to_string(&resolved_path) {
                Ok(content) => ToolExecutionResult::success(content),
                Err(e) => ToolExecutionResult::failure(format!(
                    "Failed to read {}: {}",
                    resolved_path.display(),
                    e
                )),
            }
        }
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!("Failed to write {}: {}", path, e))
                }
            };

            if let Some(line_number) = line_number {
                let existing = match fs::read_to_string(&resolved_path) {
                    Ok(content) => content,
                    Err(e) => {
                        return ToolExecutionResult::failure(format!(
                            "Failed to edit line {} in {}: {}",
                            line_number,
                            resolved_path.display(),
                            e
                        ));
                    }
                };

                let updated = match edit_line_content(&existing, line_number, &content) {
                    Ok(updated) => updated,
                    Err(e) => {
                        return ToolExecutionResult::failure(format!(
                            "Failed to edit line {} in {}: {}",
                            line_number,
                            resolved_path.display(),
                            e
                        ));
                    }
                };

                return match fs::write(&resolved_path, updated) {
                    Ok(_) => ToolExecutionResult::success(format!(
                        "Edited line {} in {}",
                        line_number,
                        resolved_path.display()
                    )),
                    Err(e) => ToolExecutionResult::failure(format!(
                        "Failed to edit line {} in {}: {}",
                        line_number,
                        resolved_path.display(),
                        e
                    )),
                };
            }

            if let Some(parent) = resolved_path.parent() {
                if !parent.exists() {
                    let _ = fs::create_dir_all(parent);
                }
            }
            match fs::write(&resolved_path, content) {
                Ok(_) => {
                    ToolExecutionResult::success(format!("Wrote to {}", resolved_path.display()))
                }
                Err(e) => ToolExecutionResult::failure(format!(
                    "Failed to write {}: {}",
                    resolved_path.display(),
                    e
                )),
            }
        }
        AgentTool::FsPatch {
            path,
            search,
            replace,
        } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Patch failed for {}: {}",
                        path, e
                    ))
                }
            };

            let existing = match fs::read_to_string(&resolved_path) {
                Ok(content) => content,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Failed to read {}: {}",
                        resolved_path.display(),
                        e
                    ));
                }
            };

            let updated = match apply_patch(&existing, &search, &replace) {
                Ok(updated) => updated,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Patch failed for {}: {}",
                        resolved_path.display(),
                        e
                    ));
                }
            };

            match fs::write(&resolved_path, updated) {
                Ok(_) => {
                    ToolExecutionResult::success(format!("Patched {}", resolved_path.display()))
                }
                Err(e) => ToolExecutionResult::failure(format!(
                    "Failed to write patch to {}: {}",
                    resolved_path.display(),
                    e
                )),
            }
        }
        AgentTool::FsList { path } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!("Failed to list {}: {}", path, e))
                }
            };

            match list_directory_entries(&resolved_path) {
                Ok(entries) => {
                    let rendered = entries
                        .into_iter()
                        .map(|(name, kind)| format!("[{}] {}", kind, name))
                        .collect::<Vec<_>>()
                        .join("\n");
                    ToolExecutionResult::success(rendered)
                }
                Err(e) => ToolExecutionResult::failure(e),
            }
        }
        AgentTool::FsSearch {
            path,
            regex,
            file_pattern,
        } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => return ToolExecutionResult::failure(format!("Search failed: {}", e)),
            };

            let task = tokio::task::spawn_blocking(move || {
                search_files(&resolved_path, &regex, file_pattern.as_deref())
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
