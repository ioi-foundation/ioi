use crate::agentic::runtime::worker_context::{
    collect_goal_literals, extract_worker_context_field, looks_like_command_literal,
    split_parent_playbook_context, PARENT_PLAYBOOK_CONTEXT_MARKER,
};
use crate::agentic::runtime::worker_templates::default_worker_role_label;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub(super) fn resolve_worker_role(
    template_id: Option<&str>,
    requested_role: Option<&str>,
) -> String {
    requested_role
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| default_worker_role_label(template_id).to_string())
}

pub(super) fn resolve_worker_name(role: &str, child_session_id: &[u8; 32]) -> String {
    let compact = role
        .split_whitespace()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("-");
    if compact.is_empty() {
        format!("Agent-{}", hex::encode(&child_session_id[0..2]))
    } else {
        format!("{}-{}", compact, hex::encode(&child_session_id[0..2]))
    }
}

fn looks_like_file_hint(value: &str) -> bool {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.chars().any(|ch| ch.is_whitespace()) {
        return false;
    }
    let normalized = trimmed.replace('\\', "/");
    let path = Path::new(trimmed);
    path.extension().is_some() || normalized.starts_with("tests/") || normalized.contains("/tests/")
}

fn parent_goal_likely_files(goal: &str) -> Vec<String> {
    let (_, parent_context) = split_parent_playbook_context(goal);
    if let Some(value) =
        parent_context.and_then(|text| extract_worker_context_field(text, &["likely_files"]))
    {
        return value
            .split(';')
            .map(str::trim)
            .filter(|candidate| !candidate.is_empty())
            .map(str::to_string)
            .collect();
    }

    let mut seen = HashSet::new();
    collect_goal_literals(goal)
        .into_iter()
        .map(|literal| literal.trim().to_string())
        .filter(|literal| looks_like_file_hint(literal))
        .filter(|literal| seen.insert(literal.to_ascii_lowercase()))
        .collect()
}

fn parent_goal_targeted_checks(goal: &str) -> Option<String> {
    let (_, parent_context) = split_parent_playbook_context(goal);
    if let Some(value) = parent_context.and_then(|text| {
        extract_worker_context_field(
            text,
            &[
                "targeted_checks",
                "targeted_check",
                "verification_plan",
                "verification",
            ],
        )
    }) {
        let trimmed = value.trim();
        if !trimmed.is_empty() {
            return Some(trimmed.to_string());
        }
    }

    collect_goal_literals(goal)
        .into_iter()
        .find(|literal| looks_like_command_literal(literal))
}

pub(crate) fn enrich_patch_build_verify_goal_with_parent_context(
    parent_goal: &str,
    raw_goal: &str,
) -> String {
    let (raw_head, raw_context) = split_parent_playbook_context(raw_goal);
    let raw_context_text = raw_context.unwrap_or("");
    let parent_head = split_parent_playbook_context(parent_goal).0;
    let mut context_lines = raw_context
        .map(|text| {
            text.lines()
                .map(str::trim_end)
                .filter(|line| !line.trim().is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut added = false;

    if !parent_head.is_empty()
        && extract_worker_context_field(
            raw_context_text,
            &["delegated_task_contract", "task_contract", "parent_goal"],
        )
        .is_none()
        && !raw_goal.contains(parent_head)
    {
        context_lines.push(format!("- delegated_task_contract: {parent_head}"));
        added = true;
    }

    if extract_worker_context_field(raw_context_text, &["likely_files"]).is_none() {
        let likely_files = parent_goal_likely_files(parent_goal);
        if !likely_files.is_empty() {
            context_lines.push(format!("- likely_files: {}", likely_files.join("; ")));
            added = true;
        }
    }

    if extract_worker_context_field(
        raw_context_text,
        &[
            "targeted_checks",
            "targeted_check",
            "verification_plan",
            "verification",
        ],
    )
    .is_none()
    {
        if let Some(targeted_checks) = parent_goal_targeted_checks(parent_goal) {
            context_lines.push(format!("- targeted_checks: {targeted_checks}"));
            added = true;
        }
    }

    if !added {
        return raw_goal.to_string();
    }

    let head = if raw_head.is_empty() {
        raw_goal.trim()
    } else {
        raw_head
    };
    format!(
        "{}\n\n{}\n{}",
        head,
        PARENT_PLAYBOOK_CONTEXT_MARKER,
        context_lines.join("\n")
    )
}

pub(super) fn enrich_delegated_child_goal(
    parent_goal: &str,
    raw_goal: &str,
    workflow_id: Option<&str>,
) -> String {
    if workflow_id.map(str::trim) == Some("patch_build_verify") {
        enrich_patch_build_verify_goal_with_parent_context(parent_goal, raw_goal)
    } else {
        raw_goal.to_string()
    }
}

pub(super) fn enrich_delegated_child_goal_with_prep(
    parent_goal: &str,
    raw_goal: &str,
    workflow_id: Option<&str>,
    prep_bundle: &crate::agentic::runtime::service::lifecycle::delegation::DelegatedChildPrepBundle,
) -> String {
    let enriched_goal = enrich_delegated_child_goal(parent_goal, raw_goal, workflow_id);
    let prep_summary = prep_bundle
        .prep_summary
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if prep_bundle.selected_skills.is_empty() && prep_summary.is_none() {
        return enriched_goal;
    }

    let (raw_head, raw_context) = split_parent_playbook_context(&enriched_goal);
    let raw_context_text = raw_context.unwrap_or("");
    let mut context_lines = raw_context
        .map(|text| {
            text.lines()
                .map(str::trim_end)
                .filter(|line| !line.trim().is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let mut added = false;

    if extract_worker_context_field(raw_context_text, &["selected_skills"]).is_none()
        && !prep_bundle.selected_skills.is_empty()
    {
        context_lines.push(format!(
            "- selected_skills: {}",
            prep_bundle.selected_skills.join(", ")
        ));
        added = true;
    }

    if extract_worker_context_field(raw_context_text, &["prep_summary"]).is_none() {
        if let Some(summary) = prep_summary {
            context_lines.push(format!("- prep_summary: {summary}"));
            added = true;
        }
    }

    if !added {
        return enriched_goal;
    }

    let head = if raw_head.is_empty() {
        enriched_goal.trim()
    } else {
        raw_head
    };
    format!(
        "{}\n\n{}\n{}",
        head,
        PARENT_PLAYBOOK_CONTEXT_MARKER,
        context_lines.join("\n")
    )
}

fn normalize_existing_goal_path(candidate: &str) -> Option<PathBuf> {
    let trimmed = candidate
        .trim()
        .trim_matches(|ch: char| matches!(ch, '"' | '\'' | '`' | ',' | ';' | ')'));
    if trimmed.is_empty() {
        return None;
    }

    let path = PathBuf::from(trimmed);
    let metadata = std::fs::metadata(&path).ok()?;
    if metadata.is_dir() {
        Some(path)
    } else {
        path.parent().map(Path::to_path_buf)
    }
}

pub(crate) fn infer_delegated_child_working_directory(
    parent_working_directory: &str,
    goal: &str,
) -> String {
    for literal in collect_goal_literals(goal) {
        if let Some(path) = normalize_existing_goal_path(&literal) {
            return path.to_string_lossy().to_string();
        }
    }

    let parent_trimmed = parent_working_directory.trim();
    if parent_trimmed.is_empty() {
        ".".to_string()
    } else {
        parent_trimmed.to_string()
    }
}
