use super::{
    apply_workspace_root_to_task, build_session_branch_snapshot, create_linked_worktree,
    parse_git_worktree_listing, remove_linked_worktree, run_git, same_workspace_path,
};
use crate::models::AgentTask;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

fn run_git_test(root: &Path, args: &[&str]) {
    run_git(root, args)
        .unwrap_or_else(|error| panic!("git {:?} failed in {}: {}", args, root.display(), error));
}

fn unique_temp_repo_path(name: &str) -> PathBuf {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "autopilot-branch-tests-{}-{}",
        name,
        uuid::Uuid::new_v4()
    ));
    path
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

fn minimal_task() -> AgentTask {
    serde_json::from_value(json!({
        "id": "task-1",
        "intent": "branch worktree validation",
        "agent": "autopilot",
        "phase": "Running",
        "progress": 0,
        "total_steps": 1,
        "current_step": "validating",
        "session_id": "session-1",
        "build_session": {
            "sessionId": "build",
            "studioSessionId": "studio",
            "workspaceRoot": "/tmp/original",
            "entryDocument": "README.md",
            "scaffoldRecipeId": "recipe",
            "packageManager": "npm",
            "buildStatus": "ready",
            "verificationStatus": "ready",
            "currentWorkerExecution": {
                "backend": "local",
                "plannerAuthority": "trusted",
                "executionState": "idle"
            },
            "currentLens": "preview",
            "retryCount": 0
        },
        "renderer_session": {
            "sessionId": "renderer",
            "studioSessionId": "studio",
            "renderer": "workspace_surface",
            "workspaceRoot": "/tmp/original",
            "entryDocument": "README.md",
            "status": "ready",
            "verificationStatus": "ready",
            "currentTab": "preview",
            "retryCount": 0
        }
    }))
    .expect("minimal task fixture")
}

#[test]
fn parse_git_worktree_listing_tracks_metadata() {
    let parsed = parse_git_worktree_listing(
        "worktree /tmp/repo\nHEAD abcdef123456\nbranch refs/heads/main\n\nworktree /tmp/linked\nHEAD 123456abcdef\nlocked checkout in use\nprunable stale metadata\n\n",
    );

    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed[0].path, "/tmp/repo");
    assert_eq!(parsed[0].branch_ref.as_deref(), Some("refs/heads/main"));
    assert_eq!(parsed[1].locked_reason.as_deref(), Some("checkout in use"));
    assert_eq!(parsed[1].prunable_reason.as_deref(), Some("stale metadata"));
}

#[test]
fn create_linked_worktree_updates_snapshot_inventory() {
    let root = init_test_repo("linked-worktree");
    let worktree = create_linked_worktree(&root, "feature/isolation", None, Some("proof"))
        .expect("create linked worktree");
    let snapshot = build_session_branch_snapshot(
        Some("session-1".to_string()),
        Some(worktree.display().to_string()),
    );

    assert_eq!(
        snapshot.current_branch.as_deref(),
        Some("feature/isolation"),
        "expected the switched worktree snapshot to report the new branch"
    );
    assert!(
        snapshot.worktrees.iter().any(|record| record.is_current
            && record.branch_name.as_deref() == Some("feature/isolation")
            && same_workspace_path(Path::new(record.path.as_str()), &worktree)),
        "expected snapshot worktree inventory to include the created linked worktree"
    );

    remove_linked_worktree(&root, &worktree).expect("remove linked worktree");
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn remove_linked_worktree_cleans_prunable_metadata() {
    let root = init_test_repo("prunable-worktree");
    let worktree = create_linked_worktree(&root, "feature/prunable", None, Some("stale"))
        .expect("create linked worktree");
    fs::remove_dir_all(&worktree).expect("remove linked worktree directory");

    let snapshot = build_session_branch_snapshot(
        Some("session-1".to_string()),
        Some(root.display().to_string()),
    );
    assert!(
        snapshot.worktrees.iter().any(|record| {
            !record.is_current
                && record.prunable
                && same_workspace_path(Path::new(record.path.as_str()), &worktree)
        }),
        "expected snapshot worktree inventory to flag the deleted linked worktree as prunable"
    );

    remove_linked_worktree(&root, &worktree).expect("remove prunable worktree");

    let refreshed = build_session_branch_snapshot(
        Some("session-1".to_string()),
        Some(root.display().to_string()),
    );
    assert!(
        !refreshed
            .worktrees
            .iter()
            .any(|record| same_workspace_path(Path::new(record.path.as_str()), &worktree)),
        "expected prunable worktree metadata to be removed from the shared snapshot"
    );

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn apply_workspace_root_to_task_updates_all_attached_sessions() {
    let mut task = minimal_task();
    assert!(apply_workspace_root_to_task(&mut task, "/tmp/isolated"));
    assert_eq!(
        task.build_session
            .as_ref()
            .map(|session| session.workspace_root.as_str()),
        Some("/tmp/isolated")
    );
    assert_eq!(
        task.renderer_session
            .as_ref()
            .map(|session| session.workspace_root.as_str()),
        Some("/tmp/isolated")
    );
}
