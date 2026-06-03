use super::{
    ensure_read_within_workspace, ensure_safe_regular_file_read,
    ensure_safe_regular_file_write_target, ensure_write_within_workspace,
    patch_apply_failure_message,
};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

fn make_temp_dir(name: &str) -> std::path::PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be valid")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "ioi-fs-handler-{}-{}-{}",
        name,
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

#[test]
fn patch_search_miss_maps_to_no_effect_after_action() {
    let message = patch_apply_failure_message(
        Path::new("/tmp/example.py"),
        "search block not found in file",
    );
    assert!(message.starts_with("ERROR_CLASS=NoEffectAfterAction"));
    assert!(message.contains("whitespace-collapsed block"));
    assert!(message.contains("changed `replace`"));
}

#[test]
fn patch_noop_maps_to_no_effect_after_action() {
    let message = patch_apply_failure_message(
        Path::new("/tmp/example.py"),
        "replacement must differ from search block",
    );
    assert!(message.starts_with("ERROR_CLASS=NoEffectAfterAction"));
    assert!(message.contains("do not retry identical search and replace"));
}

#[test]
fn malformed_patch_payload_maps_to_unexpected_state() {
    let message = patch_apply_failure_message(
        Path::new("/tmp/example.py"),
        "search block must be non-empty",
    );
    assert!(message.starts_with("ERROR_CLASS=UnexpectedState"));
}

#[test]
fn file_read_policy_rejects_directory_special_targets() {
    let dir = make_temp_dir("read-dir");
    let error =
        ensure_safe_regular_file_read(&dir, "read").expect_err("directory read should be blocked");
    assert!(error.contains("ERROR_CLASS=PolicyBlocked"));
    assert!(error.contains("only regular files"));
    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn file_read_policy_rejects_symlink_targets() {
    let dir = make_temp_dir("read-symlink");
    let target = dir.join("target.txt");
    let link = dir.join("link.txt");
    fs::write(&target, "payload").expect("target should be written");
    symlink(&target, &link).expect("symlink should be created");

    let error =
        ensure_safe_regular_file_read(&link, "read").expect_err("symlink read should be blocked");
    assert!(error.contains("ERROR_CLASS=PolicyBlocked"));
    assert!(error.contains("symlink"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn file_read_policy_rejects_paths_outside_workspace_boundary() {
    let workspace = make_temp_dir("read-boundary-workspace");
    let outside = make_temp_dir("read-boundary-outside").join("secret.txt");
    fs::write(&outside, "secret").expect("outside file should be written");

    let error = ensure_read_within_workspace(&outside, workspace.to_str(), "read")
        .expect_err("outside workspace read should be blocked");
    assert!(error.contains("ERROR_CLASS=PolicyBlocked"));
    assert!(error.contains("outside the workspace boundary"));
    let _ = fs::remove_dir_all(&workspace);
    if let Some(parent) = outside.parent() {
        let _ = fs::remove_dir_all(parent);
    }
}

#[test]
fn file_write_policy_rejects_missing_sibling_targets() {
    let base = make_temp_dir("write-boundary-base");
    let workspace = base.join("repo");
    let sibling = base.join("repo-sibling");
    fs::create_dir_all(&workspace).expect("workspace should be created");
    fs::create_dir_all(&sibling).expect("sibling should be created");
    let outside = sibling.join("new-file.txt");

    let error = ensure_write_within_workspace(&outside, workspace.to_str(), "write")
        .expect_err("missing sibling write target should be blocked");
    assert!(error.contains("ERROR_CLASS=PolicyBlocked"));
    assert!(error.contains("outside the workspace boundary"));
    let _ = fs::remove_dir_all(&base);
}

#[test]
fn file_write_policy_allows_missing_workspace_targets() {
    let workspace = make_temp_dir("write-boundary-workspace");
    let target = workspace.join("nested").join("new-file.txt");

    ensure_write_within_workspace(&target, workspace.to_str(), "write")
        .expect("missing workspace write target should be allowed");
    let _ = fs::remove_dir_all(&workspace);
}

#[cfg(unix)]
#[test]
fn file_write_policy_rejects_symlink_targets() {
    let dir = make_temp_dir("write-symlink");
    let target = dir.join("target.txt");
    let link = dir.join("link.txt");
    fs::write(&target, "payload").expect("target should be written");
    symlink(&target, &link).expect("symlink should be created");

    let error = ensure_safe_regular_file_write_target(&link, "write")
        .expect_err("symlink write should be blocked");
    assert!(error.contains("ERROR_CLASS=PolicyBlocked"));
    assert!(error.contains("symlink write targets"));
    let _ = fs::remove_dir_all(&dir);
}
