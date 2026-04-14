use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::Path;

const WORKFLOW_ROOTS: [&str; 4] = [
    ".agents/workflows",
    ".agent/workflows",
    "_agents/workflows",
    "_agent/workflows",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WorkspaceWorkflowSummary {
    pub workflow_id: String,
    pub slash_command: String,
    pub description: String,
    pub file_path: String,
    pub relative_path: String,
    pub source_root: String,
    pub source_rank: u8,
    pub step_count: usize,
    pub turbo_all: bool,
}

#[derive(Debug, Clone)]
pub(crate) struct WorkspaceWorkflowExpansion {
    pub summary: WorkspaceWorkflowSummary,
    pub markdown: String,
    pub expanded_intent: String,
    pub announcement: String,
}

#[derive(Debug, Clone)]
struct ParsedWorkspaceWorkflow {
    summary: WorkspaceWorkflowSummary,
    markdown: String,
    rendered_steps: Vec<String>,
}

fn slash_path(path: &Path) -> String {
    path.to_string_lossy().replace('\\', "/")
}

fn normalize_markdown(input: &str) -> String {
    input.replace("\r\n", "\n")
}

fn workflow_id_from_path(path: &Path) -> Option<String> {
    path.file_stem()
        .and_then(|value| value.to_str())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string)
}

fn numbered_step_content(line: &str) -> Option<&str> {
    let trimmed = line.trim_start();
    let digits = trimmed.chars().take_while(|ch| ch.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    let remainder = trimmed.get(digits..)?;
    let remainder = remainder.strip_prefix(". ")?;
    Some(remainder.trim())
}

fn parse_frontmatter_and_body(markdown: &str) -> (Option<String>, String) {
    let normalized = normalize_markdown(markdown);
    let trimmed = normalized.trim();
    if let Some(remainder) = trimmed.strip_prefix("---\n") {
        if let Some((frontmatter, body)) = remainder.split_once("\n---\n") {
            let description = frontmatter.lines().find_map(|line| {
                let (key, value) = line.split_once(':')?;
                if key.trim() != "description" {
                    return None;
                }
                let value = value.trim().trim_matches('"').trim_matches('\'');
                if value.is_empty() {
                    None
                } else {
                    Some(value.to_string())
                }
            });
            return (description, body.trim().to_string());
        }
    }
    (None, trimmed.to_string())
}

fn parse_rendered_steps(body: &str) -> (Vec<String>, bool) {
    let mut steps = Vec::new();
    let mut turbo_all = false;
    let mut turbo_next = false;
    let mut turbo_fence_after_step = false;
    let mut in_fence = false;
    let mut fence_lines: Vec<String> = Vec::new();

    for raw_line in body.lines() {
        let trimmed = raw_line.trim();
        if trimmed == "// turbo-all" {
            turbo_all = true;
            continue;
        }
        if trimmed == "// turbo" {
            turbo_next = true;
            continue;
        }
        if trimmed.starts_with("```") {
            if in_fence {
                let content = fence_lines.join("\n").trim().to_string();
                if !content.is_empty() {
                    let prefix = if turbo_all || turbo_next || turbo_fence_after_step {
                        "[command step | turbo]"
                    } else {
                        "[command step]"
                    };
                    steps.push(format!("{} {}", prefix, content));
                }
                fence_lines.clear();
                in_fence = false;
                turbo_next = false;
                turbo_fence_after_step = false;
            } else {
                in_fence = true;
            }
            continue;
        }
        if in_fence {
            fence_lines.push(raw_line.to_string());
            continue;
        }
        if let Some(step) = numbered_step_content(raw_line) {
            if !step.is_empty() {
                let step_is_turbo = turbo_all || turbo_next;
                let prefix = if step_is_turbo {
                    "[manual step | turbo]"
                } else {
                    "[manual step]"
                };
                steps.push(format!("{} {}", prefix, step));
                turbo_fence_after_step = step_is_turbo;
            }
            turbo_next = false;
        }
    }

    (steps, turbo_all)
}

fn discover_workspace_workflows_from_root(
    workspace_root: &Path,
) -> Result<Vec<ParsedWorkspaceWorkflow>, String> {
    let mut discovered = Vec::new();
    let mut seen_ids = HashSet::new();

    for (source_rank, source_root) in WORKFLOW_ROOTS.iter().enumerate() {
        let root_dir = workspace_root.join(source_root);
        if !root_dir.is_dir() {
            continue;
        }

        let mut entries = fs::read_dir(&root_dir)
            .map_err(|error| format!("Failed to read {}: {}", root_dir.display(), error))?
            .collect::<Result<Vec<_>, _>>()
            .map_err(|error| error.to_string())?;
        entries.sort_by_key(|entry| entry.file_name());

        for entry in entries {
            let path = entry.path();
            let file_type = entry.file_type().map_err(|error| error.to_string())?;
            if !file_type.is_file()
                || path.extension().and_then(|value| value.to_str()) != Some("md")
            {
                continue;
            }

            let Some(workflow_id) = workflow_id_from_path(&path) else {
                continue;
            };
            if !seen_ids.insert(workflow_id.clone()) {
                continue;
            }

            let markdown = fs::read_to_string(&path)
                .map_err(|error| format!("Failed to read {}: {}", path.display(), error))?;
            let (description, body) = parse_frontmatter_and_body(&markdown);
            let (rendered_steps, turbo_all) = parse_rendered_steps(&body);
            let description = description.unwrap_or_else(|| {
                format!(
                    "Run workspace workflow /{} from active documentation.",
                    workflow_id
                )
            });

            discovered.push(ParsedWorkspaceWorkflow {
                summary: WorkspaceWorkflowSummary {
                    workflow_id: workflow_id.clone(),
                    slash_command: format!("/{}", workflow_id),
                    description,
                    file_path: slash_path(&path),
                    relative_path: slash_path(path.strip_prefix(workspace_root).unwrap_or(&path)),
                    source_root: source_root.to_string(),
                    source_rank: source_rank as u8,
                    step_count: rendered_steps.len(),
                    turbo_all,
                },
                markdown: normalize_markdown(&markdown),
                rendered_steps,
            });
        }
    }

    Ok(discovered)
}

pub(crate) fn discover_workspace_workflows() -> Result<Vec<WorkspaceWorkflowSummary>, String> {
    let workspace_root = std::env::current_dir()
        .map_err(|error| format!("Failed to resolve workspace root: {}", error))?;
    Ok(discover_workspace_workflows_from_root(&workspace_root)?
        .into_iter()
        .map(|workflow| workflow.summary)
        .collect())
}

fn expand_workspace_workflow_intent_from_root(
    workspace_root: &Path,
    intent: &str,
) -> Result<Option<WorkspaceWorkflowExpansion>, String> {
    let trimmed = intent.trim_start();
    let Some(first_token) = trimmed.split_whitespace().next() else {
        return Ok(None);
    };
    let Some(requested_id) = first_token.strip_prefix('/') else {
        return Ok(None);
    };
    if requested_id.trim().is_empty() {
        return Ok(None);
    }

    let discovered = discover_workspace_workflows_from_root(workspace_root)?;
    let Some(workflow) = discovered
        .into_iter()
        .find(|workflow| workflow.summary.workflow_id == requested_id.trim())
    else {
        return Ok(None);
    };

    let trailing_context = trimmed[first_token.len()..].trim();
    let rendered_steps = if workflow.rendered_steps.is_empty() {
        "- No numbered steps were parsed; follow the workflow markdown directly.".to_string()
    } else {
        workflow
            .rendered_steps
            .iter()
            .enumerate()
            .map(|(index, step)| format!("{}. {}", index + 1, step))
            .collect::<Vec<_>>()
            .join("\n")
    };
    let trailing_context_block = if trailing_context.is_empty() {
        String::new()
    } else {
        format!(
            "\nADDITIONAL USER CONTEXT AFTER THE SLASH COMMAND:\n{}\n",
            trailing_context
        )
    };
    let turbo_contract = if workflow.summary.turbo_all {
        "This workflow declares `// turbo-all`, so every command step may bypass extra workflow confirmation. Runtime policy and approvals still apply."
            .to_string()
    } else {
        "Only steps or fenced command blocks immediately preceded by `// turbo` may bypass extra workflow confirmation. Runtime policy and approvals still apply."
            .to_string()
    };

    let expanded_intent = format!(
        "The user explicitly invoked workspace workflow `{slash}`.\n\
         Workflow file: {file_path}\n\
         Relative path: {relative_path}\n\
         Description: {description}\n\
         Source root precedence: {source_root}\n\
         Stop on the first failing workflow step, summarize the failure with receipts, and ask the user before resuming.\n\
         {turbo_contract}\n\n\
         PARSED WORKFLOW STEPS:\n\
         {rendered_steps}\n\
         {trailing_context_block}\n\
         ORIGINAL WORKFLOW MARKDOWN:\n\
         ```markdown\n{markdown}\n```",
        slash = workflow.summary.slash_command,
        file_path = workflow.summary.file_path,
        relative_path = workflow.summary.relative_path,
        description = workflow.summary.description,
        source_root = workflow.summary.source_root,
        turbo_contract = turbo_contract,
        rendered_steps = rendered_steps,
        trailing_context_block = trailing_context_block,
        markdown = workflow.markdown.trim(),
    );

    let announcement = format!(
        "Loaded workspace workflow {slash} from {path} ({steps} step{plural}).",
        slash = workflow.summary.slash_command,
        path = workflow.summary.file_path,
        steps = workflow.summary.step_count,
        plural = if workflow.summary.step_count == 1 {
            ""
        } else {
            "s"
        },
    );

    Ok(Some(WorkspaceWorkflowExpansion {
        summary: workflow.summary,
        markdown: workflow.markdown,
        expanded_intent,
        announcement,
    }))
}

pub(crate) fn expand_workspace_workflow_intent(
    intent: &str,
) -> Result<Option<WorkspaceWorkflowExpansion>, String> {
    let workspace_root = std::env::current_dir()
        .map_err(|error| format!("Failed to resolve workspace root: {}", error))?;
    expand_workspace_workflow_intent_from_root(&workspace_root, intent)
}

#[tauri::command]
pub fn list_workspace_workflows() -> Result<Vec<WorkspaceWorkflowSummary>, String> {
    discover_workspace_workflows()
}

#[cfg(test)]
mod tests;
