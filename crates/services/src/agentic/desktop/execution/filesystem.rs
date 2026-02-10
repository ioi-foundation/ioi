// Path: crates/services/src/agentic/desktop/execution/filesystem.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;
use std::fs;
use std::path::Path;

pub async fn handle(_exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
    match tool {
        AgentTool::FsRead { path } => match fs::read_to_string(&path) {
            Ok(content) => ToolExecutionResult::success(content),
            Err(e) => ToolExecutionResult::failure(format!("Failed to read {}: {}", path, e)),
        },
        AgentTool::FsWrite { path, content } => {
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
