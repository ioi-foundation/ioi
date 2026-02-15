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

fn resolve_home_directory() -> Result<PathBuf, String> {
    if let Some(home) = env::var_os("HOME") {
        if !home.is_empty() {
            return Ok(PathBuf::from(home));
        }
    }

    if let Some(user_profile) = env::var_os("USERPROFILE") {
        if !user_profile.is_empty() {
            return Ok(PathBuf::from(user_profile));
        }
    }

    if let (Some(home_drive), Some(home_path)) = (env::var_os("HOMEDRIVE"), env::var_os("HOMEPATH"))
    {
        if !home_drive.is_empty() && !home_path.is_empty() {
            let mut combined = PathBuf::from(home_drive);
            combined.push(home_path);
            return Ok(combined);
        }
    }

    Err("Home directory is not configured (HOME/USERPROFILE).".to_string())
}

fn expand_tilde_path(path: &str) -> Result<PathBuf, String> {
    if path == "~" {
        return resolve_home_directory();
    }

    if let Some(remainder) = path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\")) {
        return Ok(resolve_home_directory()?.join(remainder));
    }

    Ok(PathBuf::from(path))
}

fn resolve_working_directory(cwd: Option<&str>) -> Result<PathBuf, String> {
    let normalized = cwd.unwrap_or(".").trim();
    let candidate = if normalized.is_empty() {
        PathBuf::from(".")
    } else {
        expand_tilde_path(normalized)?
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

    let requested = expand_tilde_path(trimmed)?;
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

fn is_cross_device_rename_error(err: &std::io::Error) -> bool {
    // Unix EXDEV=18, Windows ERROR_NOT_SAME_DEVICE=17.
    matches!(err.raw_os_error(), Some(18) | Some(17))
}

fn copy_dir_recursive(source: &Path, destination: &Path) -> Result<(), String> {
    if !source.is_dir() {
        return Err(format!("Source '{}' is not a directory.", source.display()));
    }

    fs::create_dir_all(destination).map_err(|e| {
        format!(
            "Failed to create destination directory '{}': {}",
            destination.display(),
            e
        )
    })?;

    let walker = WalkDir::new(source)
        .follow_links(false)
        .sort_by_file_name()
        .into_iter();

    for entry in walker {
        let entry = entry.map_err(|e| format!("Directory traversal failed: {}", e))?;
        let entry_path = entry.path();
        let relative = entry_path
            .strip_prefix(source)
            .map_err(|e| format!("Failed to normalize copied path: {}", e))?;
        if relative.as_os_str().is_empty() {
            continue;
        }

        let dest_path = destination.join(relative);
        if entry.file_type().is_dir() {
            fs::create_dir_all(&dest_path).map_err(|e| {
                format!(
                    "Failed to create destination directory '{}': {}",
                    dest_path.display(),
                    e
                )
            })?;
            continue;
        }

        if entry.file_type().is_file() {
            if let Some(parent) = dest_path.parent() {
                fs::create_dir_all(parent).map_err(|e| {
                    format!(
                        "Failed to create destination parent '{}': {}",
                        parent.display(),
                        e
                    )
                })?;
            }
            fs::copy(entry_path, &dest_path).map_err(|e| {
                format!(
                    "Failed to copy '{}' to '{}': {}",
                    entry_path.display(),
                    dest_path.display(),
                    e
                )
            })?;
            continue;
        }

        return Err(format!(
            "Unsupported filesystem entry '{}' (symlinks and special files are not supported).",
            entry_path.display()
        ));
    }

    Ok(())
}

fn move_path_deterministic(
    source: &Path,
    destination: &Path,
    overwrite: bool,
) -> Result<(), String> {
    if !source.exists() {
        return Err(format!(
            "Source path '{}' does not exist.",
            source.display()
        ));
    }

    if source == destination {
        return Ok(());
    }

    remove_existing_destination(destination, overwrite)?;

    if let Some(parent) = destination.parent() {
        fs::create_dir_all(parent).map_err(|e| {
            format!(
                "Failed to create destination parent '{}': {}",
                parent.display(),
                e
            )
        })?;
    }

    match fs::rename(source, destination) {
        Ok(_) => Ok(()),
        Err(rename_err) => {
            if !is_cross_device_rename_error(&rename_err) {
                return Err(format!(
                    "Failed to move '{}' to '{}': {}",
                    source.display(),
                    destination.display(),
                    rename_err
                ));
            }

            if source.is_file() {
                fs::copy(source, destination).map_err(|e| {
                    format!(
                        "Cross-device fallback failed while copying '{}' to '{}': {}",
                        source.display(),
                        destination.display(),
                        e
                    )
                })?;
                fs::remove_file(source).map_err(|e| {
                    format!(
                        "Cross-device fallback failed while removing source '{}': {}",
                        source.display(),
                        e
                    )
                })?;
                return Ok(());
            }

            if source.is_dir() {
                copy_dir_recursive(source, destination)?;
                fs::remove_dir_all(source).map_err(|e| {
                    format!(
                        "Cross-device fallback failed while removing source directory '{}': {}",
                        source.display(),
                        e
                    )
                })?;
                return Ok(());
            }

            Err(format!(
                "Cross-device fallback does not support special filesystem entry '{}'.",
                source.display()
            ))
        }
    }
}

fn remove_existing_destination(destination: &Path, overwrite: bool) -> Result<(), String> {
    if destination.exists() {
        if !overwrite {
            return Err(format!(
                "Destination '{}' already exists. Set overwrite=true to replace it.",
                destination.display()
            ));
        }

        let remove_result = if destination.is_dir() {
            fs::remove_dir_all(destination)
        } else {
            fs::remove_file(destination)
        };
        remove_result.map_err(|e| {
            format!(
                "Failed to remove existing destination '{}': {}",
                destination.display(),
                e
            )
        })?;
    }

    Ok(())
}

fn copy_path_deterministic(
    source: &Path,
    destination: &Path,
    overwrite: bool,
) -> Result<(), String> {
    if !source.exists() {
        return Err(format!(
            "Source path '{}' does not exist.",
            source.display()
        ));
    }

    if source == destination {
        return Err("Source and destination are the same path.".to_string());
    }

    if source.is_dir() && destination.starts_with(source) {
        return Err(format!(
            "Destination '{}' cannot be inside source directory '{}'.",
            destination.display(),
            source.display()
        ));
    }

    remove_existing_destination(destination, overwrite)?;

    if source.is_file() {
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|e| {
                format!(
                    "Failed to create destination parent '{}': {}",
                    parent.display(),
                    e
                )
            })?;
        }

        fs::copy(source, destination).map_err(|e| {
            format!(
                "Failed to copy '{}' to '{}': {}",
                source.display(),
                destination.display(),
                e
            )
        })?;
        return Ok(());
    }

    if source.is_dir() {
        return copy_dir_recursive(source, destination);
    }

    Err(format!(
        "Copy does not support special filesystem entry '{}'.",
        source.display()
    ))
}

fn delete_path_deterministic(
    path: &Path,
    recursive: bool,
    ignore_missing: bool,
) -> Result<(), String> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(e) => {
            if e.kind() == std::io::ErrorKind::NotFound && ignore_missing {
                return Ok(());
            }
            if e.kind() == std::io::ErrorKind::NotFound {
                return Err(format!("Path '{}' does not exist.", path.display()));
            }
            return Err(format!(
                "Failed to inspect path '{}': {}",
                path.display(),
                e
            ));
        }
    };

    if metadata.file_type().is_symlink() || metadata.is_file() {
        return fs::remove_file(path)
            .map_err(|e| format!("Failed to delete file/symlink '{}': {}", path.display(), e));
    }

    if metadata.is_dir() {
        if !recursive {
            return Err(format!(
                "Path '{}' is a directory. Set recursive=true to delete directories.",
                path.display()
            ));
        }
        return fs::remove_dir_all(path)
            .map_err(|e| format!("Failed to delete directory '{}': {}", path.display(), e));
    }

    Err(format!(
        "Delete does not support special filesystem entry '{}'.",
        path.display()
    ))
}

fn create_directory_deterministic(path: &Path, recursive: bool) -> Result<(), String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.is_dir() {
                return Ok(());
            }
            return Err(format!(
                "Path '{}' already exists and is not a directory.",
                path.display()
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(format!(
                "Failed to inspect path '{}': {}",
                path.display(),
                e
            ));
        }
    }

    let create_result = if recursive {
        fs::create_dir_all(path)
    } else {
        fs::create_dir(path)
    };

    create_result.map_err(|e| format!("Failed to create directory '{}': {}", path.display(), e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        apply_patch, copy_path_deterministic, create_directory_deterministic,
        delete_path_deterministic, fuzzy_find_indices, list_directory_entries,
        move_path_deterministic, resolve_home_directory, resolve_tool_path, search_files,
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
    fn resolve_tool_path_expands_tilde_prefix() {
        let home = resolve_home_directory().expect("home directory should resolve");
        let resolved =
            resolve_tool_path("~/projects/ioi.txt", Some(".")).expect("path should resolve");
        assert_eq!(resolved, home.join("projects/ioi.txt"));
    }

    #[test]
    fn resolve_tool_path_expands_tilde_working_directory() {
        let home = resolve_home_directory().expect("home directory should resolve");
        let resolved = resolve_tool_path("workspace/file.txt", Some("~"))
            .expect("path should resolve against home");
        assert_eq!(resolved, home.join("workspace/file.txt"));
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

    #[test]
    fn move_path_moves_file() {
        let dir = make_temp_dir("move-file");
        let src = dir.join("src.txt");
        let dst = dir.join("nested").join("dst.txt");
        fs::write(&src, "payload").expect("source file should be written");

        move_path_deterministic(&src, &dst, false).expect("move should succeed");

        assert!(!src.exists());
        let moved = fs::read_to_string(&dst).expect("destination file should be readable");
        assert_eq!(moved, "payload");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn copy_path_copies_file() {
        let dir = make_temp_dir("copy-file");
        let src = dir.join("src.txt");
        let dst = dir.join("nested").join("dst.txt");
        fs::write(&src, "payload").expect("source file should be written");

        copy_path_deterministic(&src, &dst, false).expect("copy should succeed");

        assert!(src.exists());
        let copied = fs::read_to_string(&dst).expect("destination file should be readable");
        assert_eq!(copied, "payload");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn copy_path_requires_overwrite_for_existing_destination() {
        let dir = make_temp_dir("copy-overwrite-required");
        let src = dir.join("src.txt");
        let dst = dir.join("dst.txt");
        fs::write(&src, "src").expect("source file should be written");
        fs::write(&dst, "dst").expect("destination file should be written");

        let err = copy_path_deterministic(&src, &dst, false)
            .expect_err("copy without overwrite should fail when destination exists");
        assert!(err.contains("already exists"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn copy_path_overwrite_replaces_existing_destination() {
        let dir = make_temp_dir("copy-overwrite");
        let src = dir.join("src.txt");
        let dst = dir.join("dst.txt");
        fs::write(&src, "fresh").expect("source file should be written");
        fs::write(&dst, "stale").expect("destination file should be written");

        copy_path_deterministic(&src, &dst, true).expect("overwrite copy should succeed");

        assert!(src.exists());
        let copied = fs::read_to_string(&dst).expect("destination file should be readable");
        assert_eq!(copied, "fresh");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn copy_path_rejects_copying_directory_into_itself() {
        let dir = make_temp_dir("copy-dir-into-self");
        let src = dir.join("src");
        let dst = src.join("nested").join("copy");
        fs::create_dir_all(src.join("nested")).expect("source subtree should be created");
        fs::write(src.join("file.txt"), "payload").expect("source file should be written");

        let err = copy_path_deterministic(&src, &dst, false)
            .expect_err("copying a directory into itself should fail");
        assert!(err.contains("cannot be inside source directory"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn move_path_requires_overwrite_for_existing_destination() {
        let dir = make_temp_dir("move-overwrite-required");
        let src = dir.join("src.txt");
        let dst = dir.join("dst.txt");
        fs::write(&src, "src").expect("source file should be written");
        fs::write(&dst, "dst").expect("destination file should be written");

        let err = move_path_deterministic(&src, &dst, false)
            .expect_err("move without overwrite should fail when destination exists");
        assert!(err.contains("already exists"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn move_path_overwrite_replaces_existing_destination() {
        let dir = make_temp_dir("move-overwrite");
        let src = dir.join("src.txt");
        let dst = dir.join("dst.txt");
        fs::write(&src, "fresh").expect("source file should be written");
        fs::write(&dst, "stale").expect("destination file should be written");

        move_path_deterministic(&src, &dst, true).expect("overwrite move should succeed");

        assert!(!src.exists());
        let moved = fs::read_to_string(&dst).expect("destination file should be readable");
        assert_eq!(moved, "fresh");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_path_removes_file() {
        let dir = make_temp_dir("delete-file");
        let file = dir.join("temp.txt");
        fs::write(&file, "payload").expect("test file should be written");

        delete_path_deterministic(&file, false, false).expect("file delete should succeed");

        assert!(!file.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_path_requires_recursive_for_directories() {
        let dir = make_temp_dir("delete-dir-non-recursive");
        let nested = dir.join("nested");
        fs::create_dir_all(&nested).expect("nested dir should be created");
        fs::write(nested.join("file.txt"), "payload").expect("nested file should be written");

        let err = delete_path_deterministic(&nested, false, false)
            .expect_err("non-recursive directory delete should fail");
        assert!(err.contains("recursive=true"));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_path_recursive_removes_directory_tree() {
        let dir = make_temp_dir("delete-dir-recursive");
        let nested = dir.join("nested");
        fs::create_dir_all(nested.join("child")).expect("nested subtree should be created");
        fs::write(nested.join("child").join("file.txt"), "payload")
            .expect("nested file should be written");

        delete_path_deterministic(&nested, true, false)
            .expect("recursive directory delete should succeed");

        assert!(!nested.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delete_path_ignore_missing_treats_absent_target_as_success() {
        let dir = make_temp_dir("delete-ignore-missing");
        let missing = dir.join("nope.txt");

        delete_path_deterministic(&missing, false, true)
            .expect("ignore_missing delete should succeed");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_directory_creates_single_directory() {
        let dir = make_temp_dir("create-dir-single");
        let target = dir.join("new-dir");

        create_directory_deterministic(&target, false).expect("create dir should succeed");

        assert!(target.is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_directory_recursive_creates_parent_chain() {
        let dir = make_temp_dir("create-dir-recursive");
        let target = dir.join("a").join("b").join("c");

        create_directory_deterministic(&target, true).expect("recursive create should succeed");

        assert!(target.is_dir());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn create_directory_rejects_existing_file_path() {
        let dir = make_temp_dir("create-dir-file-collision");
        let target = dir.join("occupied");
        fs::write(&target, "payload").expect("collision file should be created");

        let err = create_directory_deterministic(&target, true)
            .expect_err("create directory should fail for file path");
        assert!(err.contains("not a directory"));

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
        AgentTool::FsCreateDirectory { path, recursive } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Create directory failed for '{}': {}",
                        path, e
                    ))
                }
            };

            match create_directory_deterministic(&resolved_path, recursive) {
                Ok(_) => ToolExecutionResult::success(format!(
                    "Created directory {}",
                    resolved_path.display()
                )),
                Err(e) => ToolExecutionResult::failure(format!("Create directory failed: {}", e)),
            }
        }
        AgentTool::FsMove {
            source_path,
            destination_path,
            overwrite,
        } => {
            let source = match resolve_tool_path(&source_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Move failed for '{}': {}",
                        source_path, e
                    ))
                }
            };
            let destination = match resolve_tool_path(&destination_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Move failed for '{}': {}",
                        destination_path, e
                    ))
                }
            };

            match move_path_deterministic(&source, &destination, overwrite) {
                Ok(_) => ToolExecutionResult::success(format!(
                    "Moved {} -> {}",
                    source.display(),
                    destination.display()
                )),
                Err(e) => ToolExecutionResult::failure(format!("Move failed: {}", e)),
            }
        }
        AgentTool::FsCopy {
            source_path,
            destination_path,
            overwrite,
        } => {
            let source = match resolve_tool_path(&source_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Copy failed for '{}': {}",
                        source_path, e
                    ))
                }
            };
            let destination = match resolve_tool_path(&destination_path, cwd) {
                Ok(path) => path,
                Err(e) => {
                    return ToolExecutionResult::failure(format!(
                        "Copy failed for '{}': {}",
                        destination_path, e
                    ))
                }
            };

            match copy_path_deterministic(&source, &destination, overwrite) {
                Ok(_) => ToolExecutionResult::success(format!(
                    "Copied {} -> {}",
                    source.display(),
                    destination.display()
                )),
                Err(e) => ToolExecutionResult::failure(format!("Copy failed: {}", e)),
            }
        }
        AgentTool::FsDelete {
            path,
            recursive,
            ignore_missing,
        } => {
            let resolved_path = match resolve_tool_path(&path, cwd) {
                Ok(path) => path,
                Err(e) => return ToolExecutionResult::failure(format!("Delete failed: {}", e)),
            };
            let existed_before = fs::symlink_metadata(&resolved_path).is_ok();

            match delete_path_deterministic(&resolved_path, recursive, ignore_missing) {
                Ok(_) => {
                    if ignore_missing && !existed_before {
                        ToolExecutionResult::success(format!(
                            "Delete no-op (path already missing): {}",
                            resolved_path.display()
                        ))
                    } else {
                        ToolExecutionResult::success(format!("Deleted {}", resolved_path.display()))
                    }
                }
                Err(e) => ToolExecutionResult::failure(format!("Delete failed: {}", e)),
            }
        }
        _ => ToolExecutionResult::failure("Unsupported FS action"),
    }
}
