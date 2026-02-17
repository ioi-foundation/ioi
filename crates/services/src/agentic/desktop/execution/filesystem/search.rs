use regex::Regex;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use walkdir::{DirEntry, WalkDir};

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

pub(super) fn search_files(
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
