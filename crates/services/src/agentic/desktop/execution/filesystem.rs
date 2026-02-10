// Path: crates/services/src/agentic/desktop/execution/filesystem.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;
use std::fs;
use std::path::Path;

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
        _ => ToolExecutionResult::failure("Unsupported FS action"),
    }
}
