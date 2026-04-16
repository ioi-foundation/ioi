use regex::Regex;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use walkdir::{DirEntry, WalkDir};

const MAX_SEARCH_MATCHES: usize = 50;
const MAX_SEARCH_FILE_BYTES: u64 = 1_000_000;
const SEARCH_EXCLUDED_DIRS: [&str; 5] = [".git", "node_modules", "target", ".artifacts", ".tmp"];

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

fn literal_filename_query(regex_pattern: &str) -> Option<String> {
    let trimmed = regex_pattern.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut literal = String::new();
    let mut chars = trimmed.chars();
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                let next = chars.next()?;
                match next {
                    '.' | '-' | '_' | '/' | '\\' | '@' => literal.push(next),
                    _ if next.is_ascii_alphanumeric() => literal.push(next),
                    _ => return None,
                }
            }
            '.' | '-' | '_' | '/' | '@' => literal.push(ch),
            _ if ch.is_ascii_alphanumeric() => literal.push(ch),
            _ => return None,
        }
    }

    if literal.is_empty()
        || !(literal.contains('.') || literal.contains('/'))
        || literal.contains(char::is_whitespace)
    {
        return None;
    }

    Some(literal)
}

fn relative_display_path(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .ok()
        .map(|relative| {
            let rendered = relative.to_string_lossy().replace('\\', "/");
            if rendered.is_empty() {
                ".".to_string()
            } else {
                format!("./{}", rendered)
            }
        })
        .unwrap_or_else(|| path.to_string_lossy().to_string())
}

fn filename_path_matches(root: &Path, literal: &str, file_filter: Option<&str>) -> Vec<String> {
    let literal_lower = literal.to_ascii_lowercase();
    let mut matches = Vec::new();

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

        let relative = relative_display_path(root, path);
        let relative_lower = relative.to_ascii_lowercase();
        let file_name_lower = path
            .file_name()
            .and_then(|value| value.to_str())
            .map(|value| value.to_ascii_lowercase())
            .unwrap_or_default();

        let exact_basename = file_name_lower == literal_lower;
        let exact_relative = relative_lower == literal_lower
            || relative_lower == format!("./{}", literal_lower.trim_start_matches("./"));
        let suffix_relative =
            relative_lower.ends_with(&format!("/{}", literal_lower.trim_start_matches("./")));
        let contains_relative = relative_lower.contains(&literal_lower);

        if !(exact_basename || exact_relative || suffix_relative || contains_relative) {
            continue;
        }

        let depth = path
            .strip_prefix(root)
            .ok()
            .map(|relative| relative.components().count())
            .unwrap_or(usize::MAX);
        let score = if exact_relative {
            0usize
        } else if exact_basename {
            1
        } else if suffix_relative {
            2
        } else {
            3
        };
        matches.push((score, depth, relative));
    }

    matches.sort_by(|left, right| {
        left.0
            .cmp(&right.0)
            .then(left.1.cmp(&right.1))
            .then(left.2.cmp(&right.2))
    });

    matches
        .into_iter()
        .take(MAX_SEARCH_MATCHES)
        .map(|(_, _, relative)| format!("FILE_MATCH {}", relative))
        .collect()
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

    if let Some(literal) = literal_filename_query(regex_pattern) {
        let path_matches = filename_path_matches(root, &literal, file_filter);
        if !path_matches.is_empty() {
            return Ok(path_matches.join("\n"));
        }
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
