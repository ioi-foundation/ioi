// Path: crates/services/src/agentic/desktop/execution/system.rs

use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;

pub async fn handle(exec: &ToolExecutor, tool: AgentTool) -> ToolExecutionResult {
    match tool {
        AgentTool::SysExec { command, args, detach } => {
            match exec.terminal.execute(&command, &args, detach).await {
                Ok(out) => ToolExecutionResult::success(out),
                Err(e) => ToolExecutionResult::failure(e.to_string()),
            }
        }
        
        AgentTool::OsLaunchApp { app_name } => {
            let app_lower = app_name.to_lowercase();
            
            // Platform specific launch logic
            let (cmd, args) = if cfg!(target_os = "macos") {
                ("open", vec!["-a".to_string(), app_name.clone()])
            } else if cfg!(target_os = "windows") {
                // Powershell Start-Process for better app resolution
                ("powershell", vec!["-Command".to_string(), format!("Start-Process '{}'", app_name)])
            } else {
                // Linux: Try gtk-launch or direct binary if known
                if app_lower.contains("calculator") {
                     ("gnome-calculator", vec![])
                } else if app_lower.contains("code") {
                     ("code", vec![])
                } else {
                     (app_name.as_str(), vec![])
                }
            };
            
            match exec.terminal.execute(cmd, &args, true).await {
                Ok(_) => ToolExecutionResult::success(format!("Launched {}", app_name)),
                Err(e) => ToolExecutionResult::failure(format!("Failed to launch {}: {}", app_name, e)),
            }
        }
        
        _ => ToolExecutionResult::failure("Unsupported System action"),
    }
}