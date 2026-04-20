use super::*;

#[test]
fn command_output_spills_after_200_lines() {
    let mut output = String::new();
    for i in 0..201 {
        output.push_str(&format!("line {}\n", i));
    }
    assert!(should_spill_command_output(&output));
}

#[test]
fn diff_spills_for_large_changes_or_many_files() {
    assert!(should_spill_diff(301, 1));
    assert!(should_spill_diff(30, 4));
    assert!(!should_spill_diff(300, 3));
}

#[test]
fn estimate_diff_stats_counts_files_and_line_changes() {
    let diff = r#"
diff --git a/a.rs b/a.rs
--- a/a.rs
+++ b/a.rs
-old
+new
diff --git a/b.rs b/b.rs
--- a/b.rs
+++ b/b.rs
-x
+y
"#;
    let (lines, files) = estimate_diff_stats(diff);
    assert_eq!(lines, 4);
    assert_eq!(files, 2);
}
