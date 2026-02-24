// Path: crates/services/src/agentic/desktop/execution/system/mod.rs

mod install;
mod launch;
mod paths;
mod receipt;
mod sys_exec;

use super::workload;
use super::{ToolExecutionResult, ToolExecutor};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{KernelEvent, WorkloadActivityKind, WorkloadReceipt};

#[derive(Clone, Debug)]
pub(super) struct LaunchAttempt {
    command: String,
    args: Vec<String>,
    detach: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SysExecInvocation {
    command: String,
    args: Vec<String>,
    shell_wrapped: bool,
}

pub(crate) use install::is_sudo_password_required_install_error;

fn compute_workload_id(
    session_id: [u8; 32],
    step_index: u32,
    tool_name: &str,
    command_preview: &str,
) -> String {
    workload::compute_workload_id(session_id, step_index, tool_name, command_preview)
}

fn extract_error_class(error: Option<&str>) -> Option<String> {
    workload::extract_error_class(error)
}

fn emit_workload_activity(
    tx: &tokio::sync::broadcast::Sender<KernelEvent>,
    session_id: [u8; 32],
    step_index: u32,
    workload_id: String,
    kind: WorkloadActivityKind,
) {
    workload::emit_workload_activity(tx, session_id, step_index, workload_id, kind);
}

fn emit_workload_receipt(
    tx: &tokio::sync::broadcast::Sender<KernelEvent>,
    session_id: [u8; 32],
    step_index: u32,
    workload_id: String,
    receipt: WorkloadReceipt,
) {
    workload::emit_workload_receipt(tx, session_id, step_index, workload_id, receipt);
}

pub async fn handle(
    exec: &ToolExecutor,
    tool: AgentTool,
    cwd: &str,
    session_id: [u8; 32],
    step_index: u32,
) -> ToolExecutionResult {
    match tool {
        AgentTool::SysExec {
            command,
            args,
            stdin,
            detach,
        } => {
            sys_exec::handle_sys_exec(
                exec, &command, &args, stdin, detach, cwd, session_id, step_index,
            )
            .await
        }

        AgentTool::SysExecSession {
            command,
            args,
            stdin,
        } => {
            sys_exec::handle_sys_exec_session(
                exec, &command, &args, stdin, cwd, session_id, step_index,
            )
            .await
        }

        AgentTool::SysExecSessionReset {} => {
            sys_exec::handle_sys_exec_session_reset(exec, cwd, session_id, step_index).await
        }

        AgentTool::SysChangeDir { path } => match paths::resolve_target_directory(cwd, &path) {
            Ok(path) => ToolExecutionResult::success(path.to_string_lossy().to_string()),
            Err(error) => ToolExecutionResult::failure(error),
        },

        AgentTool::SysInstallPackage { package, manager } => {
            install::handle_install_package(
                exec,
                cwd,
                &package,
                manager.as_deref(),
                session_id,
                step_index,
            )
            .await
        }

        AgentTool::OsLaunchApp { app_name } => launch::handle_os_launch_app(exec, &app_name).await,

        _ => ToolExecutionResult::failure("Unsupported System action"),
    }
}

#[cfg(test)]
mod tests;
