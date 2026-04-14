use std::time::Duration;

use super::stream::combine_success_output;
use super::{CommandExecutionOptions, CommandLaunchResult, TerminalDriver};

#[cfg(unix)]
async fn wait_for_retained_completion(
    driver: &TerminalDriver,
    command_id: &str,
) -> super::RetainedCommandSnapshot {
    for _ in 0..40 {
        let snapshot = driver
            .retained_command_status(command_id)
            .await
            .expect("retained command status should resolve");
        if !snapshot.running {
            return snapshot;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("retained command '{}' did not finish in time", command_id);
}

#[test]
fn combine_success_output_keeps_stdout_when_stderr_empty() {
    let output = combine_success_output("hello world\n", "");
    assert_eq!(output, "hello world");
}

#[test]
fn combine_success_output_surfaces_stderr_when_stdout_empty() {
    let output = combine_success_output("", "warning: fallback path used\n");
    assert_eq!(output, "Stderr:\nwarning: fallback path used");
}

#[test]
fn combine_success_output_labels_mixed_streams() {
    let output = combine_success_output("ready\n", "warning: cache miss\n");
    assert_eq!(output, "Stdout:\nready\nStderr:\nwarning: cache miss");
}

#[cfg(unix)]
#[tokio::test]
async fn execute_timeout_kills_command_without_hanging() {
    let driver = TerminalDriver::new();
    let started = std::time::Instant::now();
    let err = driver
        .execute_in_dir_with_options(
            "sh",
            &["-c".to_string(), "sleep 10".to_string()],
            false,
            None,
            CommandExecutionOptions::default().with_timeout(Duration::from_millis(200)),
        )
        .await
        .expect_err("sleep should time out");
    let elapsed = started.elapsed();

    assert!(
        err.to_string().to_ascii_lowercase().contains("timed out"),
        "unexpected timeout error: {}",
        err
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "timeout handling hung too long: {:?}",
        elapsed
    );
}

#[cfg(unix)]
#[tokio::test]
async fn execute_does_not_hang_when_parent_exits_before_background_child() {
    let driver = TerminalDriver::new();
    let started = std::time::Instant::now();
    let out = driver
        .execute_in_dir_with_options(
            "sh",
            &["-c".to_string(), "sleep 5 & exit 0".to_string()],
            false,
            None,
            CommandExecutionOptions::default().with_timeout(Duration::from_secs(10)),
        )
        .await
        .expect("parent shell should exit successfully");
    let elapsed = started.elapsed();

    assert!(out.trim().is_empty());
    assert!(
        elapsed < Duration::from_secs(3),
        "post-exit stream drain hung too long: {:?}",
        elapsed
    );
}

#[cfg(unix)]
#[tokio::test]
async fn session_exec_preserves_shell_state_across_calls() {
    let driver = TerminalDriver::new();
    let key = "test-session";

    let out = driver
        .execute_session_in_dir_with_options(
            key,
            "export",
            &["IOI_SESSION_TEST=ok".to_string()],
            None,
            CommandExecutionOptions::default().with_timeout(Duration::from_secs(5)),
        )
        .await
        .expect("export should succeed");
    assert!(out.trim().is_empty());

    let out = driver
        .execute_session_in_dir_with_options(
            key,
            "echo $IOI_SESSION_TEST",
            &[],
            None,
            CommandExecutionOptions::default().with_timeout(Duration::from_secs(5)),
        )
        .await
        .expect("echo should succeed");
    assert_eq!(out.trim(), "ok");

    let _ = driver.reset_session(key).await;
}

#[cfg(unix)]
#[tokio::test]
async fn session_exec_has_tty_on_unix() {
    let driver = TerminalDriver::new();
    let key = "test-session-tty";

    let out = driver
        .execute_session_in_dir_with_options(
            key,
            "sh",
            &[
                "-c".to_string(),
                "if test -t 0; then echo TTY; else echo NOTTY; fi".to_string(),
            ],
            None,
            CommandExecutionOptions::default().with_timeout(Duration::from_secs(5)),
        )
        .await
        .expect("tty probe should succeed");

    assert_eq!(out.trim(), "TTY");
    let _ = driver.reset_session(key).await;
}

#[cfg(unix)]
#[tokio::test]
async fn session_exec_stdin_heredoc_filters_prompt_echo_noise() {
    let driver = TerminalDriver::new();
    let key = "test-session-stdin-heredoc";
    let script =
        "printf 'IOI_POSTCHECK:{\"target_dir\":\"/tmp\",\"total_files\":1,\"ok\":true}\\n'\n";

    let out = driver
        .execute_session_in_dir_with_options(
            key,
            "bash",
            &["-s".to_string()],
            None,
            CommandExecutionOptions::default()
                .with_timeout(Duration::from_secs(5))
                .with_stdin_data(Some(script.as_bytes().to_vec())),
        )
        .await
        .expect("bash -s stdin script should succeed");

    assert!(out.contains("IOI_POSTCHECK:"));
    assert!(!out.contains("__IOI_RC:"));
    assert!(!out.contains("__IOI_DONE:"));
    assert!(!out.lines().any(|line| line.trim() == ">"));

    let _ = driver.reset_session(key).await;
}

#[cfg(unix)]
#[tokio::test]
async fn retained_process_command_accepts_input_and_completes() {
    let driver = TerminalDriver::new();
    let launch = driver
        .execute_in_dir_with_async_boundary(
            None,
            "bash",
            &[
                "-lc".to_string(),
                "printf 'ready\\n'; read line; printf 'echo:%s\\n' \"$line\"".to_string(),
            ],
            false,
            None,
            CommandExecutionOptions::default()
                .with_timeout(Duration::from_secs(5))
                .with_wait_before_async(Some(Duration::from_millis(50))),
        )
        .await
        .expect("retained process command should launch");

    let snapshot = match launch {
        CommandLaunchResult::Retained(snapshot) => snapshot,
        CommandLaunchResult::Completed(output) => {
            panic!("expected retained handle, got completed output: {}", output)
        }
    };

    assert!(snapshot.running);
    assert!(snapshot.terminal_id.is_none());
    assert_eq!(snapshot.command, "bash");
    assert!(snapshot.output_tail.contains("ready"));

    let after_input = driver
        .retained_command_input(&snapshot.command_id, b"hello\n")
        .await
        .expect("stdin should be forwarded");
    assert_eq!(after_input.command_id, snapshot.command_id);

    let completed = wait_for_retained_completion(&driver, &snapshot.command_id).await;
    assert!(!completed.running);
    assert_eq!(completed.exit_code, Some(0));
    assert!(completed.output_tail.contains("ready"));
    assert!(completed.output_tail.contains("echo:hello"));
}

#[cfg(unix)]
#[tokio::test]
async fn retained_session_command_tracks_terminal_id_and_accepts_input() {
    let driver = TerminalDriver::new();
    let key = "test-retained-session";
    let launch = driver
        .execute_session_in_dir_with_async_boundary(
            None,
            key,
            "bash",
            &[
                "-lc".to_string(),
                "printf 'session-ready\\n'; read line; printf 'session-echo:%s\\n' \"$line\""
                    .to_string(),
            ],
            None,
            CommandExecutionOptions::default()
                .with_timeout(Duration::from_secs(5))
                .with_wait_before_async(Some(Duration::from_millis(50))),
        )
        .await
        .expect("retained session command should launch");

    let snapshot = match launch {
        CommandLaunchResult::Retained(snapshot) => snapshot,
        CommandLaunchResult::Completed(output) => {
            panic!(
                "expected retained session handle, got completed output: {}",
                output
            )
        }
    };

    assert!(snapshot.running);
    assert_eq!(snapshot.terminal_id.as_deref(), Some(key));

    let after_input = driver
        .retained_command_input(&snapshot.command_id, b"workspace\n")
        .await
        .expect("session stdin should be forwarded");
    assert_eq!(after_input.terminal_id.as_deref(), Some(key));

    let completed = wait_for_retained_completion(&driver, &snapshot.command_id).await;
    assert!(!completed.running);
    assert_eq!(completed.exit_code, Some(0));
    assert!(completed.output_tail.contains("session-ready"));
    assert!(completed.output_tail.contains("session-echo:workspace"));

    let _ = driver.reset_session(key).await;
}

#[cfg(windows)]
#[tokio::test]
async fn session_exec_preserves_shell_state_across_calls() {
    let driver = TerminalDriver::new();
    let key = "test-session";

    let out = driver
        .execute_session_in_dir_with_options(
            key,
            "set",
            &["IOI_SESSION_TEST=ok".to_string()],
            None,
            CommandExecutionOptions::default().with_timeout(Duration::from_secs(5)),
        )
        .await
        .expect("set should succeed");
    assert!(out.trim().is_empty());

    let out = driver
        .execute_session_in_dir_with_options(
            key,
            "echo %IOI_SESSION_TEST%",
            &[],
            None,
            CommandExecutionOptions::default().with_timeout(Duration::from_secs(5)),
        )
        .await
        .expect("echo should succeed");
    assert_eq!(out.trim(), "ok");

    let _ = driver.reset_session(key).await;
}
