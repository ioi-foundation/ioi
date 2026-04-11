pub(crate) const PARENT_PLAYBOOK_CONTEXT_MARKER: &str = "[PARENT PLAYBOOK CONTEXT]";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CommandLiteralHeuristic {
    Loose,
    Strict,
}

pub(crate) fn normalize_whitespace(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

pub(crate) fn split_parent_playbook_context(goal: &str) -> (&str, Option<&str>) {
    if let Some((head, tail)) = goal.split_once(PARENT_PLAYBOOK_CONTEXT_MARKER) {
        (head.trim(), Some(tail.trim()))
    } else {
        (goal.trim(), None)
    }
}

pub(crate) fn normalize_worker_context_key(key: &str) -> String {
    key.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

pub(crate) fn extract_worker_context_field(text: &str, keys: &[&str]) -> Option<String> {
    let normalized_keys = keys
        .iter()
        .map(|key| normalize_worker_context_key(key))
        .collect::<Vec<_>>();
    for line in text.lines() {
        let trimmed = line
            .trim()
            .trim_start_matches('-')
            .trim_start_matches('*')
            .trim();
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        if normalized_keys
            .iter()
            .any(|candidate| *candidate == normalize_worker_context_key(key))
        {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    None
}

pub(crate) fn collect_goal_literals(goal: &str) -> Vec<String> {
    let mut literals = Vec::new();
    let mut current = String::new();
    let mut delimiter: Option<char> = None;

    for ch in goal.chars() {
        if let Some(active) = delimiter {
            if ch == active {
                let trimmed = current.trim();
                if !trimmed.is_empty() {
                    literals.push(trimmed.to_string());
                }
                current.clear();
                delimiter = None;
            } else {
                current.push(ch);
            }
            continue;
        }

        if matches!(ch, '"' | '\'' | '`') {
            delimiter = Some(ch);
        }
    }

    literals
}

pub(crate) fn looks_like_command_literal(value: &str) -> bool {
    matches_command_literal(value, CommandLiteralHeuristic::Loose)
}

pub(crate) fn matches_command_literal(value: &str, heuristic: CommandLiteralHeuristic) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return false;
    }

    match heuristic {
        CommandLiteralHeuristic::Loose => {
            let lowered = trimmed.to_ascii_lowercase();
            lowered.contains("python")
                || lowered.contains("cargo")
                || lowered.contains("pytest")
                || lowered.contains("unittest")
                || lowered.contains("npm")
                || lowered.contains("pnpm")
                || lowered.contains("yarn")
                || lowered.contains("bash")
                || trimmed.contains(' ')
        }
        CommandLiteralHeuristic::Strict => {
            if !trimmed.contains(' ') {
                return false;
            }

            let first = trimmed
                .split_whitespace()
                .next()
                .unwrap_or_default()
                .trim_matches(|ch: char| !ch.is_ascii_alphanumeric() && ch != '_' && ch != '-');
            matches!(
                first,
                "python"
                    | "python3"
                    | "pytest"
                    | "cargo"
                    | "npm"
                    | "pnpm"
                    | "yarn"
                    | "node"
                    | "uv"
                    | "go"
                    | "bash"
                    | "sh"
                    | "make"
                    | "just"
            )
        }
    }
}
