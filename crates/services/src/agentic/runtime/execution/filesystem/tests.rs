use super::{
    apply_patch, copy_path_deterministic, create_directory_deterministic,
    create_zip_from_directory_deterministic, delete_path_deterministic, edit_line_content,
    fuzzy_find_indices, list_directory_entries, move_path_deterministic, resolve_home_directory,
    resolve_tool_path, search_files, stat_path_deterministic,
};
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use zip::ZipArchive;

fn make_temp_dir(name: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time should be after epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "ioi-services-fs-test-{}-{}-{}",
        name,
        std::process::id(),
        nanos
    ));
    fs::create_dir_all(&dir).expect("test temp directory should be created");
    dir
}

#[test]
fn fuzzy_patch_handles_indentation_mismatch() {
    let original = "def hello():\n    print(\"Hello\")\n    return True\n";
    let search = "  print(\"Hello\")\n  return True";
    let replace = "    print(\"World\")\n    return False";

    let updated = apply_patch(original, search, replace).expect("fuzzy patch should succeed");
    assert!(updated.contains("print(\"World\")"));
    assert!(updated.contains("return False"));
}

#[test]
fn fuzzy_match_reports_ambiguity() {
    let source = "key = 1\nkey =  1\n";
    let search = "key = 1";
    let err = fuzzy_find_indices(source, search).expect_err("fuzzy match should be ambiguous");
    assert!(err.contains("ambiguous"));
}

#[test]
fn edit_line_content_recovers_python_return_when_line_number_is_out_of_range() {
    let original = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
    );

    let updated = edit_line_content(
        original,
        14,
        "return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\")",
    )
    .expect("structural return replacement should succeed");

    assert!(updated.contains("replace(\"//\", \"/\")"));
    assert!(!updated.contains("return raw_path.strip().replace(\"\\\\\", \"/\")\n"));
}

#[test]
fn apply_patch_recovers_python_function_block_when_search_uses_summarized_view() {
    let original = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
    );
    let summarized_search = concat!(
        "def normalize_fixture_path(raw_path: str) -> str: ",
        "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\" ",
        "return raw_path.strip().replace(\"\\\\\", \"/\")"
    );
    let replace = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        " normalized = raw_path.strip().replace(\"\\\\\", \"/\")\n",
        " while \"//\" in normalized:\n",
        "  normalized = normalized.replace(\"//\", \"/\")\n",
        " return normalized\n"
    );

    let updated =
        apply_patch(original, summarized_search, replace).expect("structural patch should succeed");

    assert!(updated.contains("while \"//\" in normalized:"));
    assert!(updated.contains("return normalized"));
    assert!(!updated.contains("return raw_path.strip().replace(\"\\\\\", \"/\")"));
}

#[test]
fn apply_patch_recovers_multiline_python_function_from_single_line_reference() {
    let original =
        "def normalize_fixture_path(raw_path: str) -> str: return raw_path.strip().replace(\"\\\\\", \"/\")\n";
    let summarized_search = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")"
    );
    let replace = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    normalized = raw_path.strip().replace(\"\\\\\", \"/\")\n",
        "    while \"//\" in normalized:\n",
        "        normalized = normalized.replace(\"//\", \"/\")\n",
        "    return normalized\n"
    );

    let updated =
        apply_patch(original, summarized_search, replace).expect("structural patch should succeed");

    assert!(updated.contains("\n    \"\"\"Normalize a repo-relative path"));
    assert!(updated.contains("while \"//\" in normalized:"));
    assert!(updated.contains("return normalized"));
    assert!(!updated.contains(": return raw_path.strip().replace(\"\\\\\", \"/\")"));
}

#[test]
fn resolve_tool_path_uses_working_directory_for_relative_paths() {
    let cwd = std::env::current_dir().expect("current dir should resolve");
    let cwd_str = cwd.to_string_lossy().to_string();
    let resolved =
        resolve_tool_path("nested/file.txt", Some(&cwd_str)).expect("path should resolve");
    assert_eq!(resolved, cwd.join("nested/file.txt"));
}

#[test]
fn resolve_tool_path_preserves_absolute_paths() {
    let cwd = std::env::current_dir().expect("current dir should resolve");
    let absolute = cwd.join("absolute.txt");
    let absolute_str = absolute.to_string_lossy().to_string();
    let resolved = resolve_tool_path(&absolute_str, Some(".")).expect("absolute path should pass");
    assert_eq!(resolved, absolute);
}

#[test]
fn resolve_tool_path_expands_tilde_prefix() {
    let home = resolve_home_directory().expect("home directory should resolve");
    let resolved = resolve_tool_path("~/projects/ioi.txt", Some(".")).expect("path should resolve");
    assert_eq!(resolved, home.join("projects/ioi.txt"));
}

#[test]
fn resolve_tool_path_expands_tilde_working_directory() {
    let home = resolve_home_directory().expect("home directory should resolve");
    let resolved = resolve_tool_path("workspace/file.txt", Some("~"))
        .expect("path should resolve against home");
    assert_eq!(resolved, home.join("workspace/file.txt"));
}

#[test]
fn list_directory_entries_returns_sorted_output() {
    let dir = make_temp_dir("list-order");
    fs::write(dir.join("zeta.txt"), "z").expect("zeta file should be written");
    fs::write(dir.join("alpha.txt"), "a").expect("alpha file should be written");
    fs::create_dir_all(dir.join("beta")).expect("beta dir should be created");

    let listing = list_directory_entries(&dir).expect("listing should succeed");
    let rendered: Vec<String> = listing
        .into_iter()
        .map(|(name, kind)| format!("[{}] {}", kind, name))
        .collect();

    assert_eq!(rendered, vec!["[F] alpha.txt", "[D] beta", "[F] zeta.txt"]);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn search_files_traversal_is_sorted_by_filename() {
    let dir = make_temp_dir("search-order");
    fs::write(dir.join("b.txt"), "needle in b").expect("b file should be written");
    fs::write(dir.join("a.txt"), "needle in a").expect("a file should be written");

    let output = search_files(&dir, "needle", Some("*.txt")).expect("search should succeed");
    let lines: Vec<&str> = output.lines().collect();

    assert_eq!(lines.len(), 2);
    assert!(lines[0].contains("a.txt:1: needle in a"));
    assert!(lines[1].contains("b.txt:1: needle in b"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn search_files_prioritizes_literal_filename_matches() {
    let dir = make_temp_dir("search-filename-literal");
    fs::write(dir.join("package.json"), "{\n  \"name\": \"root\"\n}")
        .expect("root package file should be written");
    fs::create_dir_all(dir.join("apps/app")).expect("nested app dir should be created");
    fs::write(
        dir.join("apps/app/package.json"),
        "{\n  \"name\": \"nested\"\n}",
    )
    .expect("nested package file should be written");
    fs::write(
        dir.join("README.md"),
        "See package.json for the available scripts.",
    )
    .expect("readme should be written");

    let output = search_files(&dir, "package\\.json", None).expect("search should succeed");
    let lines: Vec<&str> = output.lines().collect();

    assert_eq!(lines[0], "FILE_MATCH ./package.json");
    assert_eq!(lines[1], "FILE_MATCH ./apps/app/package.json");
    assert_eq!(lines.len(), 2);

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn search_files_excludes_noisy_hidden_build_dirs_from_content_matches() {
    let dir = make_temp_dir("search-excluded-hidden");
    fs::create_dir_all(dir.join(".artifacts/cache")).expect("artifact cache dir should exist");
    fs::create_dir_all(dir.join(".tmp/cache")).expect("tmp cache dir should exist");
    fs::write(
        dir.join(".artifacts/cache/noisy.txt"),
        "needle in artifact cache",
    )
    .expect("artifact cache file should be written");
    fs::write(dir.join(".tmp/cache/noisy.txt"), "needle in tmp cache")
        .expect("tmp cache file should be written");
    fs::write(dir.join("src.txt"), "needle in source").expect("source file should be written");

    let output = search_files(&dir, "needle", Some("*.txt")).expect("search should succeed");
    let lines: Vec<&str> = output.lines().collect();

    assert_eq!(lines.len(), 1);
    assert!(lines[0].contains("src.txt:1: needle in source"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn stat_path_reports_expected_metadata_fields() {
    let dir = make_temp_dir("stat");
    let file_path = dir.join("example.txt");
    fs::write(&file_path, "payload").expect("file should be written");

    let payload =
        stat_path_deterministic(&file_path).expect("stat tool should return serialized payload");
    let parsed: serde_json::Value =
        serde_json::from_str(&payload).expect("stat payload should be valid json");

    assert_eq!(
        parsed.get("path").and_then(|value| value.as_str()),
        Some(file_path.to_string_lossy().as_ref())
    );
    assert_eq!(
        parsed.get("entry_type").and_then(|value| value.as_str()),
        Some("file")
    );
    assert_eq!(
        parsed.get("size_bytes").and_then(|value| value.as_u64()),
        Some(7)
    );
    assert!(
        parsed
            .get("modified_epoch_ms")
            .and_then(|value| value.as_u64())
            .is_some(),
        "modified_epoch_ms should be present for regular files"
    );

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn move_path_moves_file() {
    let dir = make_temp_dir("move-file");
    let src = dir.join("src.txt");
    let dst = dir.join("nested").join("dst.txt");
    fs::write(&src, "payload").expect("source file should be written");

    move_path_deterministic(&src, &dst, false).expect("move should succeed");

    assert!(!src.exists());
    let moved = fs::read_to_string(&dst).expect("destination file should be readable");
    assert_eq!(moved, "payload");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn copy_path_copies_file() {
    let dir = make_temp_dir("copy-file");
    let src = dir.join("src.txt");
    let dst = dir.join("nested").join("dst.txt");
    fs::write(&src, "payload").expect("source file should be written");

    copy_path_deterministic(&src, &dst, false).expect("copy should succeed");

    assert!(src.exists());
    let copied = fs::read_to_string(&dst).expect("destination file should be readable");
    assert_eq!(copied, "payload");

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn copy_path_rejects_symlink_source() {
    let dir = make_temp_dir("copy-symlink-source");
    let source_target = dir.join("source-target.txt");
    let source_link = dir.join("source-link.txt");
    let destination = dir.join("copied.txt");
    fs::write(&source_target, "payload").expect("source target should be written");
    symlink(&source_target, &source_link).expect("source symlink should be created");

    let err = copy_path_deterministic(&source_link, &destination, false)
        .expect_err("symlink source should be rejected");
    assert!(err.contains("symlink source"));
    assert!(!destination.exists());

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn copy_path_overwrite_replaces_symlink_destination_only() {
    let dir = make_temp_dir("copy-symlink-destination-overwrite");
    let source = dir.join("source.txt");
    let destination_target = dir.join("destination-target.txt");
    let destination_link = dir.join("destination-link.txt");
    fs::write(&source, "fresh").expect("source file should be written");
    fs::write(&destination_target, "keep").expect("destination target should be written");
    symlink(&destination_target, &destination_link).expect("destination symlink should be created");

    copy_path_deterministic(&source, &destination_link, true)
        .expect("overwrite copy should replace symlink path");

    let copied = fs::read_to_string(&destination_link).expect("destination file should exist");
    assert_eq!(copied, "fresh");
    let target =
        fs::read_to_string(&destination_target).expect("symlink target should remain untouched");
    assert_eq!(target, "keep");
    assert!(!fs::symlink_metadata(&destination_link)
        .expect("destination metadata should exist")
        .file_type()
        .is_symlink());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn copy_path_requires_overwrite_for_existing_destination() {
    let dir = make_temp_dir("copy-overwrite-required");
    let src = dir.join("src.txt");
    let dst = dir.join("dst.txt");
    fs::write(&src, "src").expect("source file should be written");
    fs::write(&dst, "dst").expect("destination file should be written");

    let err = copy_path_deterministic(&src, &dst, false)
        .expect_err("copy without overwrite should fail when destination exists");
    assert!(err.contains("already exists"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn copy_path_overwrite_replaces_existing_destination() {
    let dir = make_temp_dir("copy-overwrite");
    let src = dir.join("src.txt");
    let dst = dir.join("dst.txt");
    fs::write(&src, "fresh").expect("source file should be written");
    fs::write(&dst, "stale").expect("destination file should be written");

    copy_path_deterministic(&src, &dst, true).expect("overwrite copy should succeed");

    assert!(src.exists());
    let copied = fs::read_to_string(&dst).expect("destination file should be readable");
    assert_eq!(copied, "fresh");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn copy_path_rejects_copying_directory_into_itself() {
    let dir = make_temp_dir("copy-dir-into-self");
    let src = dir.join("src");
    let dst = src.join("nested").join("copy");
    fs::create_dir_all(src.join("nested")).expect("source subtree should be created");
    fs::write(src.join("file.txt"), "payload").expect("source file should be written");

    let err = copy_path_deterministic(&src, &dst, false)
        .expect_err("copying a directory into itself should fail");
    assert!(err.contains("cannot be inside source directory"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn move_path_rejects_moving_directory_into_itself() {
    let dir = make_temp_dir("move-dir-into-self");
    let src = dir.join("src");
    let dst = src.join("nested").join("moved");
    fs::create_dir_all(src.join("nested")).expect("source subtree should be created");
    fs::write(src.join("file.txt"), "payload").expect("source file should be written");

    let err = move_path_deterministic(&src, &dst, false)
        .expect_err("moving a directory into itself should fail");
    assert!(err.contains("cannot be inside source directory"));
    assert!(src.exists());
    assert!(!dst.exists());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn move_path_requires_overwrite_for_existing_destination() {
    let dir = make_temp_dir("move-overwrite-required");
    let src = dir.join("src.txt");
    let dst = dir.join("dst.txt");
    fs::write(&src, "src").expect("source file should be written");
    fs::write(&dst, "dst").expect("destination file should be written");

    let err = move_path_deterministic(&src, &dst, false)
        .expect_err("move without overwrite should fail when destination exists");
    assert!(err.contains("already exists"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn move_path_overwrite_replaces_existing_destination() {
    let dir = make_temp_dir("move-overwrite");
    let src = dir.join("src.txt");
    let dst = dir.join("dst.txt");
    fs::write(&src, "fresh").expect("source file should be written");
    fs::write(&dst, "stale").expect("destination file should be written");

    move_path_deterministic(&src, &dst, true).expect("overwrite move should succeed");

    assert!(!src.exists());
    let moved = fs::read_to_string(&dst).expect("destination file should be readable");
    assert_eq!(moved, "fresh");

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn move_path_overwrite_replaces_symlink_destination_only() {
    let dir = make_temp_dir("move-symlink-destination-overwrite");
    let source = dir.join("source.txt");
    let destination_target = dir.join("destination-target.txt");
    let destination_link = dir.join("destination-link.txt");
    fs::write(&source, "fresh").expect("source file should be written");
    fs::write(&destination_target, "keep").expect("destination target should be written");
    symlink(&destination_target, &destination_link).expect("destination symlink should be created");

    move_path_deterministic(&source, &destination_link, true)
        .expect("overwrite move should replace symlink path");

    let moved = fs::read_to_string(&destination_link).expect("destination file should exist");
    assert_eq!(moved, "fresh");
    let target =
        fs::read_to_string(&destination_target).expect("symlink target should remain untouched");
    assert_eq!(target, "keep");
    assert!(!source.exists());
    assert!(!fs::symlink_metadata(&destination_link)
        .expect("destination metadata should exist")
        .file_type()
        .is_symlink());

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn delete_path_removes_file() {
    let dir = make_temp_dir("delete-file");
    let file = dir.join("temp.txt");
    fs::write(&file, "payload").expect("test file should be written");

    delete_path_deterministic(&file, false, false).expect("file delete should succeed");

    assert!(!file.exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn delete_path_requires_recursive_for_directories() {
    let dir = make_temp_dir("delete-dir-non-recursive");
    let nested = dir.join("nested");
    fs::create_dir_all(&nested).expect("nested dir should be created");
    fs::write(nested.join("file.txt"), "payload").expect("nested file should be written");

    let err = delete_path_deterministic(&nested, false, false)
        .expect_err("non-recursive directory delete should fail");
    assert!(err.contains("recursive=true"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn delete_path_recursive_removes_directory_tree() {
    let dir = make_temp_dir("delete-dir-recursive");
    let nested = dir.join("nested");
    fs::create_dir_all(nested.join("child")).expect("nested subtree should be created");
    fs::write(nested.join("child").join("file.txt"), "payload")
        .expect("nested file should be written");

    delete_path_deterministic(&nested, true, false)
        .expect("recursive directory delete should succeed");

    assert!(!nested.exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn delete_path_ignore_missing_treats_absent_target_as_success() {
    let dir = make_temp_dir("delete-ignore-missing");
    let missing = dir.join("nope.txt");

    delete_path_deterministic(&missing, false, true).expect("ignore_missing delete should succeed");

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn create_directory_creates_single_directory() {
    let dir = make_temp_dir("create-dir-single");
    let target = dir.join("new-dir");

    create_directory_deterministic(&target, false).expect("create dir should succeed");

    assert!(target.is_dir());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn create_directory_recursive_creates_parent_chain() {
    let dir = make_temp_dir("create-dir-recursive");
    let target = dir.join("a").join("b").join("c");

    create_directory_deterministic(&target, true).expect("recursive create should succeed");

    assert!(target.is_dir());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn create_directory_rejects_existing_file_path() {
    let dir = make_temp_dir("create-dir-file-collision");
    let target = dir.join("occupied");
    fs::write(&target, "payload").expect("collision file should be created");

    let err = create_directory_deterministic(&target, true)
        .expect_err("create directory should fail for file path");
    assert!(err.contains("not a directory"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn create_zip_archives_directory_entries_deterministically() {
    let dir = make_temp_dir("create-zip");
    let source = dir.join("Projects");
    let nested = source.join("src");
    let destination = dir.join("Projects.zip");
    fs::create_dir_all(&nested).expect("source tree should be created");
    fs::write(source.join("README.md"), "hello").expect("readme should be written");
    fs::write(nested.join("main.rs"), "fn main() {}").expect("main should be written");

    let entries = create_zip_from_directory_deterministic(&source, &destination, false)
        .expect("zip creation should succeed");
    assert!(destination.is_file());
    assert!(entries.iter().any(|entry| entry == "README.md"));
    assert!(entries.iter().any(|entry| entry == "src/"));
    assert!(entries.iter().any(|entry| entry == "src/main.rs"));

    let file = fs::File::open(&destination).expect("zip should be readable");
    let mut archive = ZipArchive::new(file).expect("zip archive should parse");
    let mut readme = String::new();
    archive
        .by_name("README.md")
        .expect("README should be present")
        .read_to_string(&mut readme)
        .expect("README should read");
    assert_eq!(readme, "hello");

    let _ = fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn create_zip_rejects_symlink_entries() {
    let dir = make_temp_dir("create-zip-symlink");
    let source = dir.join("Projects");
    let destination = dir.join("Projects.zip");
    fs::create_dir_all(&source).expect("source tree should be created");
    let real = source.join("real.txt");
    let link = source.join("link.txt");
    fs::write(&real, "payload").expect("real file should be written");
    symlink(&real, &link).expect("symlink should be created");

    let err = create_zip_from_directory_deterministic(&source, &destination, false)
        .expect_err("zip should reject symlink");
    assert!(err.contains("symlink"));
    assert!(!destination.exists());

    let _ = fs::remove_dir_all(&dir);
}
