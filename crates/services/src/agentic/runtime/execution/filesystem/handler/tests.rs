use super::{
    ensure_safe_regular_file_read, ensure_safe_regular_file_write_target,
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
    assert!(message.contains("file__write"));
    assert!(message.contains("line_number"));
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
