use super::*;
use std::fs;
use std::time::{Duration, Instant};

fn unique_temp_repo_path(name: &str) -> PathBuf {
    let timestamp = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("timestamp")
        .as_nanos();
    std::env::temp_dir().join(format!("autopilot-workspace-{name}-{timestamp}"))
}

fn run_git_test(root: &PathBuf, args: &[&str]) {
    run_git(root, args)
        .unwrap_or_else(|error| panic!("git {:?} failed in {}: {}", args, root.display(), error));
}

fn init_test_repo(name: &str) -> PathBuf {
    let root = unique_temp_repo_path(name);
    fs::create_dir_all(&root).expect("create temp repo");
    run_git_test(&root, &["init"]);
    run_git_test(&root, &["config", "user.name", "Autopilot Test"]);
    run_git_test(
        &root,
        &["config", "user.email", "autopilot-test@example.com"],
    );
    fs::write(root.join("tracked.txt"), "initial\n").expect("write tracked file");
    run_git_test(&root, &["add", "--", "tracked.txt"]);
    run_git_test(&root, &["commit", "-m", "Initial commit"]);
    root
}

#[test]
fn workspace_terminal_validation() {
    let root = std::env::current_dir().expect("current directory");
    let session = spawn_terminal_session(&root, 80, 24).expect("spawn terminal session");

    {
        let mut writer = session.writer.lock().expect("terminal writer");
        writer
            .write_all(b"printf 'autopilot-terminal-validation\\n'\nexit\n")
            .expect("write terminal commands");
        writer.flush().expect("flush terminal commands");
    }

    let deadline = Instant::now() + Duration::from_secs(8);
    let mut transcript = String::new();

    while Instant::now() < deadline {
        transcript = session
            .output
            .lock()
            .expect("terminal output")
            .iter()
            .map(|chunk| chunk.text.as_str())
            .collect::<String>();

        if transcript.contains("autopilot-terminal-validation")
            && !session.running.load(Ordering::Relaxed)
        {
            break;
        }

        thread::sleep(Duration::from_millis(50));
    }

    let _ = session.killer.lock().expect("terminal killer").kill();

    assert!(
        transcript.contains("autopilot-terminal-validation"),
        "expected PTY transcript to contain validation marker, got:\n{}",
        transcript
    );
}

#[test]
fn workspace_commit_requires_staged_changes() {
    let root = init_test_repo("commit-requires-staging");
    fs::write(root.join("tracked.txt"), "updated without staging\n").expect("update tracked file");

    let error = commit_workspace(&root, "Unstaged edit", None).expect_err("commit should fail");
    assert!(
        error.contains("Stage at least one change before committing."),
        "unexpected error: {}",
        error
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn workspace_commit_records_latest_summary() {
    let root = init_test_repo("commit-success");
    fs::write(root.join("tracked.txt"), "updated and staged\n").expect("update tracked file");
    run_git_test(&root, &["add", "--", "tracked.txt"]);

    let receipt =
        commit_workspace(&root, "Stage success", Some("Body copy")).expect("commit should succeed");

    assert_eq!(receipt.committed_file_count, 1);
    assert_eq!(receipt.remaining_change_count, 0);
    assert!(receipt.state.entries.is_empty());
    assert!(receipt.state.git.branch.is_some());
    assert!(
        receipt.commit_summary.contains("Stage success"),
        "commit summary missing headline: {}",
        receipt.commit_summary
    );

    let _ = fs::remove_dir_all(&root);
}
