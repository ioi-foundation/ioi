use std::time::Duration;

use super::stream::combine_success_output;
use super::{CommandExecutionOptions, TerminalDriver};

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
