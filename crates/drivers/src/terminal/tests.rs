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
