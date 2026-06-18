use super::ignore::is_ignored_workspace_path;
use regex::Regex;
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use walkdir::{DirEntry, WalkDir};

const MAX_SEARCH_MATCHES: usize = 50;
const MAX_SEARCH_FILE_BYTES: u64 = 1_000_000;
const SEARCH_EXCLUDED_DIRS: [&str; 20] = [
    ".agents",
    ".artifacts",
    ".git",
    ".internal",
    ".ioi",
    ".next",
    ".tmp",
    ".turbo",
    ".vite",
    "build",
    "coverage",
    "dist",
    "docs/evidence",
    "examples",
    "ide",
    "internal-docs",
    "ioi-data",
    "node_modules",
    "out",
    "target",
];

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
    if !entry.file_type().is_dir() {
        return false;
    }

    let name = entry.file_name().to_string_lossy();
    let path = entry.path().to_string_lossy().replace('\\', "/");
    SEARCH_EXCLUDED_DIRS.iter().any(|excluded| {
        name == *excluded || path.ends_with(&format!("/{}", excluded.trim_matches('/')))
    })
}

fn is_generated_search_file(path: &Path) -> bool {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();

    matches!(
        extension.as_str(),
        "avif"
            | "bin"
            | "bmp"
            | "gif"
            | "ico"
            | "jpg"
            | "jpeg"
            | "map"
            | "mp3"
            | "mp4"
            | "ogg"
            | "pdf"
            | "png"
            | "so"
            | "wasm"
            | "webp"
            | "woff"
            | "woff2"
            | "zip"
    ) || file_name.ends_with(".min.js")
        || file_name.ends_with(".min.css")
        || file_name.ends_with(".bundle.js")
        || file_name.ends_with(".bundle.css")
        || file_name.ends_with(".chunk.js")
        || file_name.ends_with(".chunk.css")
        || file_name.ends_with(".generated.js")
        || file_name.ends_with(".generated.ts")
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

fn simple_regex_terms(regex_pattern: &str) -> Vec<String> {
    let stop_words = [
        "about", "and", "are", "does", "from", "how", "into", "look", "or", "per", "repo", "the",
        "this", "what", "where", "which",
    ];
    regex_pattern
        .split('|')
        .filter_map(|raw| {
            let mut term = String::new();
            let mut chars = raw.trim().chars();
            while let Some(ch) = chars.next() {
                match ch {
                    '\\' => {
                        let next = chars.next()?;
                        if next.is_ascii_alphanumeric()
                            || matches!(next, '.' | '-' | '_' | '/' | '@')
                        {
                            term.push(next);
                        } else {
                            return None;
                        }
                    }
                    _ if ch.is_ascii_alphanumeric()
                        || matches!(ch, '.' | '-' | '_' | '/' | '@') =>
                    {
                        term.push(ch)
                    }
                    _ => return None,
                }
            }
            let term = term.trim().to_ascii_lowercase();
            if term.len() < 3 || stop_words.iter().any(|stop| term == *stop) {
                None
            } else {
                Some(term)
            }
        })
        .collect()
}

fn path_hidden_rank(relative_path: &str) -> usize {
    relative_path
        .trim_start_matches("./")
        .split('/')
        .any(|part| part.starts_with('.') && part.len() > 1)
        .into()
}

fn source_path_rank(relative_path: &str) -> usize {
    let path = relative_path.trim_start_matches("./");
    if path.starts_with("apps/")
        || path.starts_with("crates/")
        || path.starts_with("packages/")
        || path.starts_with("src/")
        || path.starts_with("scripts/")
    {
        0
    } else if path.starts_with('.') {
        2
    } else {
        1
    }
}

fn search_noise_rank(relative_path: &str) -> usize {
    let path = relative_path.trim_start_matches("./");
    let path_parts = path.split('/').collect::<Vec<_>>();
    if path.contains("/native-fixture-")
        || path.contains("/fixtures/")
        || path.contains("/__fixtures__/")
        || path.contains("/test-fixtures/")
        || path_parts
            .iter()
            .any(|part| matches!(*part, "test" | "tests" | "__tests__"))
        || path.ends_with(".test.js")
        || path.ends_with(".test.mjs")
        || path.ends_with(".test.rs")
        || path.ends_with("/tests.rs")
        || path.ends_with("tests.rs")
        || path.ends_with(".spec.js")
        || path.ends_with(".spec.mjs")
        || path.ends_with(".spec.ts")
        || path.ends_with("hypervisor-session-workbench-scenarios.mjs")
    {
        1
    } else {
        0
    }
}

fn path_term_score(relative_path: &str, terms: &[String]) -> usize {
    if terms.is_empty() {
        return 0;
    }
    let path = relative_path.trim_start_matches("./").to_ascii_lowercase();
    terms
        .iter()
        .filter(|term| path.contains(term.as_str()))
        .count()
}

fn search_match_score(relative_path: &str, line: &str, terms: &[String]) -> usize {
    if terms.is_empty() {
        return 0;
    }
    let haystack = format!(
        "{} {}",
        relative_path.to_ascii_lowercase(),
        line.to_ascii_lowercase()
    );
    terms
        .iter()
        .filter(|term| haystack.contains(term.as_str()))
        .count()
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
        if is_ignored_workspace_path(path, root.to_str()) {
            continue;
        }
        if is_generated_search_file(path) {
            continue;
        }
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
    let scoring_terms = simple_regex_terms(regex_pattern);
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
        if is_ignored_workspace_path(path, root.to_str()) {
            continue;
        }
        if is_generated_search_file(path) {
            continue;
        }

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
                let relative = relative_display_path(root, path);
                let rendered = format!("{}:{}: {}", path.display(), line_idx + 1, line.trim());
                matches.push((
                    source_path_rank(&relative),
                    search_noise_rank(&relative),
                    std::cmp::Reverse(path_term_score(&relative, &scoring_terms)),
                    std::cmp::Reverse(search_match_score(&relative, &line, &scoring_terms)),
                    path_hidden_rank(&relative),
                    path.strip_prefix(root)
                        .ok()
                        .map(|relative| relative.components().count())
                        .unwrap_or(usize::MAX),
                    relative,
                    line_idx,
                    rendered,
                ));
            }
        }
    }

    if matches.is_empty() {
        Ok("No matches found.".to_string())
    } else {
        matches.sort_by(|left, right| {
            left.0
                .cmp(&right.0)
                .then(left.1.cmp(&right.1))
                .then(left.2.cmp(&right.2))
                .then(left.3.cmp(&right.3))
                .then(left.4.cmp(&right.4))
                .then(left.5.cmp(&right.5))
                .then(left.6.cmp(&right.6))
                .then(left.7.cmp(&right.7))
        });
        let truncated = matches.len() > MAX_SEARCH_MATCHES;
        let mut rendered = matches
            .into_iter()
            .take(MAX_SEARCH_MATCHES)
            .map(|(_, _, _, _, _, _, _, _, rendered)| rendered)
            .collect::<Vec<_>>();
        if truncated {
            rendered.push("... [truncated: too many matches] ...".to_string());
        }
        Ok(rendered.join("\n"))
    }
}
