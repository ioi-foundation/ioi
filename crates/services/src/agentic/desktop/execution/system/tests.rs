use super::install::classify_install_failure;
use super::launch::{
    build_linux_launch_plan, launch_attempt_failed, launch_errors_indicate_missing_app,
    quote_powershell_single_quoted_string,
};
use super::paths::{resolve_home_directory, resolve_target_directory, resolve_working_directory};
use super::receipt::redact_args_for_receipt;
use super::sys_exec::{
    append_sys_exec_command_history, classify_sys_exec_failure, command_output_indicates_failure,
    extract_exit_code, normalize_stdin_data, parse_terminal_output, resolve_sys_exec_invocation,
    resolve_sys_exec_timeout, summarize_sys_exec_failure_output, sys_exec_failure_result,
    COMMAND_HISTORY_PREFIX, SYS_EXEC_DEFAULT_TIMEOUT, SYS_EXEC_EXTENDED_TIMEOUT,
};
use super::{LaunchAttempt, ToolExecutionResult};
use crate::agentic::desktop::execution::workload::WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER;
use crate::agentic::desktop::types::CommandExecution;
use async_trait::async_trait;
use ioi_api::vm::drivers::gui::{GuiDriver, InputEvent};
use ioi_api::vm::drivers::os::{OsDriver, WindowInfo};
use ioi_api::vm::inference::{mock::MockInferenceRuntime, InferenceRuntime};
use ioi_drivers::browser::BrowserDriver;
use ioi_drivers::mcp::McpManager;
use ioi_drivers::terminal::TerminalDriver;
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{
    ActionRequest, ContextSlice, KernelEvent, WorkloadActivityKind, WorkloadReceipt,
};
use ioi_types::error::VmError;
use std::sync::Arc;

#[test]
fn powershell_single_quoted_string_escapes_apostrophes() {
    assert_eq!(
        quote_powershell_single_quoted_string("O'Reilly"),
        "'O''Reilly'"
    );
}

#[test]
fn powershell_single_quoted_string_strips_newlines() {
    assert_eq!(quote_powershell_single_quoted_string("a\r\nb"), "'a b'");
}

#[test]
fn sys_exec_timeout_defaults_for_simple_commands() {
    let timeout = resolve_sys_exec_timeout("ls", &["-la".to_string()], false);
    assert_eq!(timeout, SYS_EXEC_DEFAULT_TIMEOUT);
}

#[test]
fn sys_exec_timeout_extends_for_shell_wrappers() {
    let timeout = resolve_sys_exec_timeout(
        "bash",
        &["-lc".to_string(), "cargo test".to_string()],
        false,
    );
    assert_eq!(timeout, SYS_EXEC_EXTENDED_TIMEOUT);
}

#[test]
fn sys_exec_timeout_extends_for_build_subcommands() {
    let timeout = resolve_sys_exec_timeout("git", &["clone".to_string()], false);
    assert_eq!(timeout, SYS_EXEC_EXTENDED_TIMEOUT);
}

#[test]
fn sys_exec_invocation_preserves_explicit_args() {
    let args = vec!["status".to_string(), "--short".to_string()];
    let invocation =
        resolve_sys_exec_invocation("git", &args).expect("invocation should normalize");

    assert_eq!(invocation.command, "git");
    assert_eq!(invocation.args, args);
    assert!(!invocation.shell_wrapped);
}

#[test]
fn sys_exec_invocation_merges_inline_tokens_with_explicit_args() {
    let args = vec!["HEAD~1".to_string()];
    let invocation = resolve_sys_exec_invocation("git show", &args)
        .expect("inline command tokens should merge with explicit args");

    assert_eq!(invocation.command, "git");
    assert_eq!(
        invocation.args,
        vec!["show".to_string(), "HEAD~1".to_string()]
    );
    assert!(!invocation.shell_wrapped);
}

#[test]
fn sys_exec_invocation_preserves_windows_style_paths_with_spaces_when_args_present() {
    let command = r"C:\Program Files\Git\bin\git.exe";
    let args = vec!["--version".to_string()];
    let invocation = resolve_sys_exec_invocation(command, &args)
        .expect("paths with spaces should not be split into inline tokens");

    assert_eq!(invocation.command, command);
    assert_eq!(invocation.args, args);
    assert!(!invocation.shell_wrapped);
}

#[test]
fn sys_exec_invocation_splits_plain_command_string() {
    let invocation = resolve_sys_exec_invocation("git status --short", &[])
        .expect("plain command string should split");

    assert_eq!(invocation.command, "git");
    assert_eq!(
        invocation.args,
        vec!["status".to_string(), "--short".to_string()]
    );
    assert!(!invocation.shell_wrapped);
}

#[test]
fn sys_exec_invocation_shell_wraps_pipeline_syntax() {
    let invocation = resolve_sys_exec_invocation("cat Cargo.toml | head -n 1", &[])
        .expect("pipeline syntax should wrap via shell");

    assert!(invocation.shell_wrapped);
    if cfg!(target_os = "windows") {
        assert!(invocation.command.to_ascii_lowercase().ends_with("cmd.exe"));
        assert!(invocation.args.iter().any(|arg| arg == "/C"));
    } else {
        assert_eq!(invocation.args.first(), Some(&"-lc".to_string()));
    }
}

#[test]
fn sys_exec_invocation_shell_wraps_builtins_with_explicit_args() {
    let args = vec!["/tmp/my project".to_string()];
    let invocation = resolve_sys_exec_invocation("cd", &args).expect("shell builtins should wrap");

    assert!(invocation.shell_wrapped);
    if cfg!(target_os = "windows") {
        assert!(invocation.command.to_ascii_lowercase().ends_with("cmd.exe"));
        assert!(invocation.args.iter().any(|arg| arg == "/C"));
    } else {
        assert_eq!(invocation.args.first(), Some(&"-lc".to_string()));
        let command_line = invocation
            .args
            .get(1)
            .expect("shell command should be passed as second arg");
        assert!(command_line.contains("cd"));
        assert!(command_line.contains("'/tmp/my project'"));
    }
}

#[test]
fn sys_exec_invocation_shell_wraps_env_assignment_prefix() {
    let invocation = resolve_sys_exec_invocation("FOO=bar npm run test", &[])
        .expect("env-prefix commands should wrap via shell");

    if cfg!(target_os = "windows") {
        assert!(!invocation.shell_wrapped);
        assert_eq!(invocation.command, "FOO=bar");
    } else {
        assert!(invocation.shell_wrapped);
        assert_eq!(invocation.args.first(), Some(&"-lc".to_string()));
        assert_eq!(
            invocation.args.get(1),
            Some(&"FOO=bar npm run test".to_string())
        );
    }
}

#[test]
fn linux_plan_prefers_gtk_launch_when_available() {
    let plan = build_linux_launch_plan("Google Chrome", true);
    assert!(!plan.is_empty());
    assert_eq!(plan[0].command, "gtk-launch");
    assert!(plan
        .iter()
        .any(|a| a.command == "gtk-launch" && a.args.iter().any(|arg| arg == "google-chrome")));
}

#[test]
fn linux_plan_includes_generic_binary_fallbacks() {
    let plan = build_linux_launch_plan("Google Chrome", false);
    let commands: Vec<&str> = plan.iter().map(|a| a.command.as_str()).collect();
    assert!(commands.contains(&"google-chrome"));
    assert!(commands.contains(&"google_chrome"));
}

#[test]
fn detects_terminal_non_zero_output_banner() {
    assert!(command_output_indicates_failure(
        "Command failed: exit status: 1\nStderr: launch failed"
    ));
    assert!(!command_output_indicates_failure(
        "Launched background process 'code' (PID: 1234)"
    ));
}

#[test]
fn blocking_launch_attempt_treats_non_zero_output_as_failure() {
    let blocking = LaunchAttempt {
        command: "gtk-launch".to_string(),
        args: vec!["calculator".to_string()],
        detach: false,
    };
    assert!(launch_attempt_failed(
        &blocking,
        "Command failed: exit status: 1\nStderr: not found"
    ));
}

#[test]
fn detached_launch_attempt_does_not_parse_banner_as_failure() {
    let detached = LaunchAttempt {
        command: "calculator".to_string(),
        args: vec![],
        detach: true,
    };
    assert!(!launch_attempt_failed(
        &detached,
        "Command failed: exit status: 1\nStderr: not found"
    ));
}

#[test]
fn classify_missing_app_errors_as_tool_unavailable() {
    let errors = vec![
        "gnome-calculator (No such file or directory)".to_string(),
        "gtk-launch gnome-calculator (non-zero exit: Command failed: exit status: 1)".to_string(),
    ];
    assert!(launch_errors_indicate_missing_app(&errors));
}

#[test]
fn do_not_classify_generic_runtime_errors_as_missing_app() {
    let errors = vec!["google-chrome (Command timed out after 5 seconds)".to_string()];
    assert!(!launch_errors_indicate_missing_app(&errors));
}

#[test]
fn classify_mixed_sudo_and_package_lookup_as_missing_dependency() {
    let mixed = "[sudo] password for user: sudo: a password is required\nE: Unable to locate package calculator";
    assert_eq!(
        classify_install_failure(mixed, "sudo", "apt-get"),
        "MissingDependency"
    );
}

#[test]
fn classify_password_required_as_permission_error() {
    let password = "sudo: a password is required";
    assert_eq!(
        classify_install_failure(password, "sudo", "apt-get"),
        "PermissionOrApprovalRequired"
    );
}

#[test]
fn classify_sys_exec_not_found_as_tool_unavailable() {
    let err = "Command failed: exit status: 127\nStderr: bash: fooctl: command not found";
    assert_eq!(classify_sys_exec_failure(err, "fooctl"), "ToolUnavailable");
}

#[test]
fn classify_sys_exec_not_found_with_compound_command_as_tool_unavailable() {
    let err = "Command failed: exit status: 127\nStderr: bash: fooctl: command not found";
    assert_eq!(
        classify_sys_exec_failure(err, "fooctl --version"),
        "ToolUnavailable"
    );
}

#[test]
fn classify_sys_exec_timeout_as_timeout_or_hang() {
    let err = "Command timed out after 5 seconds.";
    assert_eq!(classify_sys_exec_failure(err, "sleep"), "TimeoutOrHang");
}

#[test]
fn summarize_sys_exec_failure_prefers_stderr_payload() {
    let err = "Command failed: exit status: 1\nStderr: permission denied";
    assert_eq!(summarize_sys_exec_failure_output(err), "permission denied");
}

#[test]
fn sys_exec_failure_result_emits_error_class_prefix() {
    let result = sys_exec_failure_result(
        "fooctl",
        "Command failed: exit status: 127\nStderr: fooctl: command not found",
    );
    assert!(!result.success);
    assert!(result.history_entry.is_none());
    let err = result.error.expect("error payload must exist");
    assert!(err.starts_with("ERROR_CLASS=ToolUnavailable"));
}

#[test]
fn append_sys_exec_command_history_uses_exit_code_prefix_and_split_output() {
    let mut result = ToolExecutionResult::failure("command output");
    let output = "Command failed: exit status: 127\nStderr: boom\n";
    result.history_entry = Some(output.to_string());
    append_sys_exec_command_history(&mut result, "fooctl --version", 42, 9);
    assert!(result.history_entry.is_some());
    let entry = result.history_entry.as_deref().unwrap_or("");
    assert!(entry.starts_with(COMMAND_HISTORY_PREFIX));
    let payload = &entry[COMMAND_HISTORY_PREFIX.len()..];
    let json_payload = payload.lines().next().unwrap_or("").trim();
    let parsed = match serde_json::from_str::<CommandExecution>(json_payload) {
        Ok(value) => value,
        Err(error) => panic!("history json should parse: {}", error),
    };
    assert_eq!(parsed.command, "fooctl --version");
    assert_eq!(parsed.exit_code, 127);
    assert_eq!(parsed.stderr, "boom");
    assert_eq!(parsed.step_index, 42);
}

#[test]
fn append_sys_exec_command_history_falls_back_to_provided_exit_code_when_missing() {
    let mut result = ToolExecutionResult::failure("command output");
    let output = "Command output without a numeric exit status line";
    result.history_entry = Some(output.to_string());
    append_sys_exec_command_history(&mut result, "echo hi", 7, 9);
    let entry = result.history_entry.as_deref().unwrap_or("");
    let payload = &entry[COMMAND_HISTORY_PREFIX.len()..];
    let json_payload = payload.lines().next().unwrap_or("").trim();
    let parsed = match serde_json::from_str::<CommandExecution>(json_payload) {
        Ok(value) => value,
        Err(error) => panic!("history json should parse: {}", error),
    };
    assert_eq!(parsed.exit_code, 9);
    assert_eq!(parsed.command, "echo hi");
}

#[test]
fn extract_exit_code_parses_terminal_exit_status() {
    let output = "Command failed: exit status: 127\nStderr: boom";
    assert_eq!(extract_exit_code(output), Some(127));
}

#[test]
fn parse_terminal_output_splits_stdout_and_stderr() {
    let output = "line one\nline two\nStderr: boom on stderr";
    let (stdout, stderr) = parse_terminal_output(output);
    assert_eq!(stdout, "line one\nline two");
    assert_eq!(stderr, "boom on stderr");
}

#[test]
fn resolve_working_directory_expands_tilde_home() {
    let home = resolve_home_directory().expect("home directory should resolve");
    let resolved = resolve_working_directory("~").expect("tilde working directory should resolve");
    assert_eq!(resolved, home);
}

#[test]
fn resolve_target_directory_expands_tilde_path() {
    let expected =
        std::fs::canonicalize(resolve_home_directory().expect("home directory should resolve"))
            .expect("canonical home path should resolve");
    let resolved =
        resolve_target_directory(".", "~").expect("tilde target directory should resolve");
    assert_eq!(resolved, expected);
}

#[test]
fn normalize_stdin_data_preserves_non_empty_payload() {
    let stdin = normalize_stdin_data(Some("line1\nline2".to_string()));
    assert_eq!(stdin, Some(b"line1\nline2".to_vec()));
}

#[test]
fn normalize_stdin_data_drops_empty_payload() {
    assert!(normalize_stdin_data(Some(String::new())).is_none());
    assert!(normalize_stdin_data(None).is_none());
}

#[test]
fn workload_receipt_arg_redaction_redacts_sensitive_values() {
    let args = vec![
        "--password".to_string(),
        "super-secret".to_string(),
        "--token=abc123".to_string(),
        "--user=user:pass".to_string(),
        "ok".to_string(),
        "API_KEY=hunter2".to_string(),
        "--header".to_string(),
        "Authorization: Bearer jwt.jwt.jwt".to_string(),
    ];

    let redacted = redact_args_for_receipt(&args);
    assert_eq!(redacted.len(), args.len());
    assert_eq!(redacted[0], "--password");
    assert_eq!(
        redacted[1],
        WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER.to_string()
    );
    assert_eq!(
        redacted[2],
        format!("--token={}", WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER)
    );
    assert_eq!(
        redacted[3],
        format!("--user={}", WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER)
    );
    assert_eq!(redacted[4], "ok");
    assert_eq!(
        redacted[5],
        format!("API_KEY={}", WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER)
    );
    assert_eq!(
        redacted[7],
        format!(
            "Authorization: Bearer {}",
            WORKLOAD_RECEIPT_REDACTED_PLACEHOLDER
        )
    );
}

struct NoopGuiDriver;

#[async_trait]
impl GuiDriver for NoopGuiDriver {
    async fn capture_screen(
        &self,
        _crop_rect: Option<(i32, i32, u32, u32)>,
    ) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn capture_raw_screen(&self) -> Result<Vec<u8>, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn capture_tree(&self) -> Result<String, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn capture_context(&self, _intent: &ActionRequest) -> Result<ContextSlice, VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn inject_input(&self, _event: InputEvent) -> Result<(), VmError> {
        Err(VmError::HostError("noop gui".into()))
    }

    async fn get_element_center(&self, _id: u32) -> Result<Option<(u32, u32)>, VmError> {
        Ok(None)
    }

    async fn register_som_overlay(
        &self,
        _map: std::collections::HashMap<u32, (i32, i32, i32, i32)>,
    ) -> Result<(), VmError> {
        Ok(())
    }
}

struct NoopOsDriver;

#[async_trait]
impl OsDriver for NoopOsDriver {
    async fn get_active_window_title(&self) -> Result<Option<String>, VmError> {
        Ok(None)
    }

    async fn get_active_window_info(&self) -> Result<Option<WindowInfo>, VmError> {
        Ok(None)
    }

    async fn focus_window(&self, _title_query: &str) -> Result<bool, VmError> {
        Ok(false)
    }

    async fn set_clipboard(&self, _content: &str) -> Result<(), VmError> {
        Ok(())
    }

    async fn get_clipboard(&self) -> Result<String, VmError> {
        Ok(String::new())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn sys_exec_session_reset_emits_workload_receipt_and_activity() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);

    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let os: Arc<dyn OsDriver> = Arc::new(NoopOsDriver);
    let terminal = Arc::new(TerminalDriver::new());
    let browser = Arc::new(BrowserDriver::new());
    let mcp = Arc::new(McpManager::new());
    let inference: Arc<dyn InferenceRuntime> = Arc::new(MockInferenceRuntime::default());

    let exec = crate::agentic::desktop::execution::ToolExecutor::new(
        gui,
        os,
        terminal,
        browser,
        mcp,
        Some(tx),
        None,
        inference,
        None,
    );

    let session_id = [9u8; 32];
    let step_index = 7u32;
    let result = super::handle(
        &exec,
        AgentTool::SysExecSessionReset {},
        ".",
        session_id,
        step_index,
    )
    .await;

    assert!(result.success);

    let mut activity_phases: Vec<String> = Vec::new();
    let mut activity_workload_id: Option<String> = None;
    let mut receipt_workload_id: Option<String> = None;
    let mut saw_exec_receipt = false;

    while let Ok(ev) = rx.try_recv() {
        match ev {
            KernelEvent::WorkloadActivity(activity) => {
                assert_eq!(activity.session_id, session_id);
                assert_eq!(activity.step_index, step_index);
                if let Some(existing) = activity_workload_id.as_ref() {
                    assert_eq!(existing, &activity.workload_id);
                } else {
                    activity_workload_id = Some(activity.workload_id.clone());
                }
                if let WorkloadActivityKind::Lifecycle { phase, .. } = activity.kind {
                    activity_phases.push(phase);
                }
            }
            KernelEvent::WorkloadReceipt(receipt_event) => {
                assert_eq!(receipt_event.session_id, session_id);
                assert_eq!(receipt_event.step_index, step_index);
                receipt_workload_id = Some(receipt_event.workload_id.clone());
                match receipt_event.receipt {
                    WorkloadReceipt::Exec(exec_receipt) => {
                        assert_eq!(exec_receipt.tool_name, "sys__exec_session_reset");
                        assert_eq!(exec_receipt.command, "sys__exec_session_reset");
                        assert!(exec_receipt.args.is_empty());
                        assert!(!exec_receipt.detach);
                        assert_eq!(exec_receipt.timeout_ms, 0);
                        assert!(exec_receipt.success);
                        assert_eq!(exec_receipt.command_preview, "sys__exec_session_reset");
                        saw_exec_receipt = true;
                    }
                    other => panic!("expected Exec receipt, got {:?}", other),
                }
            }
            _ => {}
        }
    }

    assert_eq!(
        activity_phases,
        vec!["started".to_string(), "completed".to_string()]
    );
    assert!(saw_exec_receipt);
    assert_eq!(activity_workload_id, receipt_workload_id);
}
