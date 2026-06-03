use super::boundary::canonicalize_existing_or_intended;
use std::fs;
use std::path::{Component, Path};

pub(super) fn ensure_not_ignored_workspace_path(
    path: &Path,
    cwd: Option<&str>,
    operation: &str,
) -> Result<(), String> {
    let Some(cwd) = cwd else {
        return Ok(());
    };
    let workspace_root = Path::new(cwd).canonicalize().map_err(|error| {
        format!(
            "Failed to inspect workspace ignore policy before {}: {}",
            operation, error
        )
    })?;
    let canonical_path = canonicalize_existing_or_intended(path).map_err(|error| {
        format!(
            "Failed to inspect {} before {}: {}",
            path.display(),
            operation,
            error
        )
    })?;
    if !canonical_path.starts_with(&workspace_root) {
        return Ok(());
    }
    let relative = match canonical_path.strip_prefix(&workspace_root) {
        Ok(value) => value,
        Err(_) => return Ok(()),
    };
    if relative
        .components()
        .any(|component| matches!(component, Component::Normal(value) if value == ".git"))
    {
        return Err(format!(
            "ERROR_CLASS=PolicyBlocked Refusing to {} {}: ignored workspace control files are protected.",
            operation,
            path.display()
        ));
    }
    if workspace_ignore_patterns_match(&workspace_root, relative) {
        return Err(format!(
            "ERROR_CLASS=PolicyBlocked Refusing to {} {}: ignored workspace files are protected.",
            operation,
            path.display()
        ));
    }
    Ok(())
}

pub(super) fn is_ignored_workspace_path(path: &Path, cwd: Option<&str>) -> bool {
    let Some(cwd) = cwd else {
        return false;
    };
    let Ok(workspace_root) = Path::new(cwd).canonicalize() else {
        return false;
    };
    let Ok(canonical_path) = canonicalize_existing_or_intended(path) else {
        return false;
    };
    if !canonical_path.starts_with(&workspace_root) {
        return false;
    }
    let Ok(relative) = canonical_path.strip_prefix(&workspace_root) else {
        return false;
    };
    relative
        .components()
        .any(|component| matches!(component, Component::Normal(value) if value == ".git"))
        || workspace_ignore_patterns_match(&workspace_root, relative)
}

fn workspace_ignore_patterns_match(workspace_root: &Path, relative_path: &Path) -> bool {
    let relative_text = path_to_slash_string(relative_path);
    if relative_text.is_empty() {
        return false;
    }

    let mut ignored = false;
    let mut cursor = workspace_root.to_path_buf();
    let mut ignore_files = vec![workspace_root.join(".gitignore")];
    for component in relative_path
        .parent()
        .unwrap_or_else(|| Path::new(""))
        .components()
    {
        if let Component::Normal(value) = component {
            cursor.push(value);
            ignore_files.push(cursor.join(".gitignore"));
        }
    }

    for ignore_file in ignore_files {
        let Ok(contents) = fs::read_to_string(ignore_file) else {
            continue;
        };
        for raw_line in contents.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let negated = line.starts_with('!');
            let pattern = line.trim_start_matches('!').trim();
            if pattern.is_empty() {
                continue;
            }
            if ignore_pattern_matches(pattern, relative_path) {
                ignored = !negated;
            }
        }
    }

    ignored
}

fn path_to_slash_string(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn ignore_pattern_matches(pattern: &str, relative_path: &Path) -> bool {
    let directory_pattern = pattern.ends_with('/');
    let normalized = pattern.trim_start_matches('/').trim_end_matches('/').trim();
    if normalized.is_empty() {
        return false;
    }

    let relative_text = path_to_slash_string(relative_path);
    let components = relative_path
        .components()
        .filter_map(|component| match component {
            Component::Normal(value) => Some(value.to_string_lossy().to_string()),
            _ => None,
        })
        .collect::<Vec<_>>();

    if pattern.contains('/') || pattern.starts_with('/') {
        if directory_pattern {
            return relative_text == normalized
                || relative_text
                    .strip_prefix(normalized)
                    .map(|rest| rest.starts_with('/'))
                    .unwrap_or(false);
        }
        return wildcard_match(normalized, &relative_text);
    }

    if directory_pattern {
        return components
            .iter()
            .any(|component| wildcard_match(normalized, component));
    }

    components
        .last()
        .map(|name| wildcard_match(normalized, name))
        .unwrap_or(false)
        || components
            .iter()
            .any(|component| wildcard_match(normalized, component))
}

fn wildcard_match(pattern: &str, text: &str) -> bool {
    let pattern = pattern.as_bytes();
    let text = text.as_bytes();
    let (mut p, mut t) = (0usize, 0usize);
    let mut star = None;
    let mut star_text = 0usize;

    while t < text.len() {
        if p < pattern.len() && (pattern[p] == b'?' || pattern[p] == text[t]) {
            p += 1;
            t += 1;
        } else if p < pattern.len() && pattern[p] == b'*' {
            star = Some(p);
            p += 1;
            star_text = t;
        } else if let Some(star_index) = star {
            p = star_index + 1;
            star_text += 1;
            t = star_text;
        } else {
            return false;
        }
    }

    while p < pattern.len() && pattern[p] == b'*' {
        p += 1;
    }

    p == pattern.len()
}

#[cfg(test)]
mod tests {
    use super::ensure_not_ignored_workspace_path;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn make_temp_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time should be valid")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "ioi-fs-ignore-{}-{}-{}",
            name,
            std::process::id(),
            nanos
        ));
        fs::create_dir_all(&dir).expect("temp dir should be created");
        dir
    }

    #[test]
    fn blocks_git_control_files() {
        let workspace = make_temp_dir("git-control");
        let git_dir = workspace.join(".git");
        fs::create_dir_all(&git_dir).expect("git dir should be created");
        let config = git_dir.join("config");
        fs::write(&config, "secret").expect("config should be written");

        let error = ensure_not_ignored_workspace_path(&config, workspace.to_str(), "read")
            .expect_err("git control file should be protected");
        assert!(error.contains("ERROR_CLASS=PolicyBlocked"));
        assert!(error.contains("control files"));
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn blocks_root_gitignored_file() {
        let workspace = make_temp_dir("root-pattern");
        fs::write(workspace.join(".gitignore"), "secret.txt\n").expect("gitignore");
        let secret = workspace.join("secret.txt");
        fs::write(&secret, "secret").expect("secret should be written");

        let error = ensure_not_ignored_workspace_path(&secret, workspace.to_str(), "read")
            .expect_err("ignored file should be protected");
        assert!(error.contains("ERROR_CLASS=PolicyBlocked"));
        assert!(error.contains("ignored workspace files"));
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn blocks_ignored_directory_children() {
        let workspace = make_temp_dir("dir-pattern");
        fs::write(workspace.join(".gitignore"), "private/\n").expect("gitignore");
        let secret = workspace.join("private").join("token.txt");
        fs::create_dir_all(secret.parent().expect("secret parent")).expect("private dir");
        fs::write(&secret, "secret").expect("secret should be written");

        let error = ensure_not_ignored_workspace_path(&secret, workspace.to_str(), "read")
            .expect_err("ignored directory child should be protected");
        assert!(error.contains("ERROR_CLASS=PolicyBlocked"));
        let _ = fs::remove_dir_all(&workspace);
    }

    #[test]
    fn allows_negated_gitignore_entry() {
        let workspace = make_temp_dir("negated-pattern");
        fs::write(workspace.join(".gitignore"), "*.log\n!keep.log\n").expect("gitignore");
        let keep = workspace.join("keep.log");
        fs::write(&keep, "ok").expect("file should be written");

        ensure_not_ignored_workspace_path(&keep, workspace.to_str(), "read")
            .expect("negated ignored file should be readable");
        let _ = fs::remove_dir_all(&workspace);
    }
}
