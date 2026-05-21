use super::{
    apply_exclude_file_context_path, apply_pin_file_context_path, apply_remove_file_context_path,
    dedupe_paths, normalize_path, push_front_unique, retain_without_path,
};
use crate::models::SessionFileContext;

fn sample_context() -> SessionFileContext {
    SessionFileContext {
        session_id: Some("session-123".to_string()),
        workspace_root: "/tmp/repo".to_string(),
        pinned_files: Vec::new(),
        recent_files: Vec::new(),
        explicit_includes: Vec::new(),
        explicit_excludes: Vec::new(),
        updated_at_ms: 0,
    }
}

#[test]
fn normalize_path_trims_and_drops_current_dir_marker() {
    assert_eq!(
        normalize_path("./apps/autopilot/src/main.tsx").as_deref(),
        Some("apps/autopilot/src/main.tsx")
    );
    assert_eq!(normalize_path("   "), None);
    assert_eq!(normalize_path("."), None);
}

#[test]
fn push_front_unique_promotes_and_truncates() {
    let mut paths = vec!["a.ts".to_string(), "b.ts".to_string(), "c.ts".to_string()];
    push_front_unique(&mut paths, "b.ts".to_string(), 3);
    assert_eq!(paths, vec!["b.ts", "a.ts", "c.ts"]);

    push_front_unique(&mut paths, "d.ts".to_string(), 3);
    assert_eq!(paths, vec!["d.ts", "b.ts", "a.ts"]);
}

#[test]
fn retain_without_path_removes_exact_match() {
    let mut paths = vec!["a.ts".to_string(), "b.ts".to_string()];
    assert!(retain_without_path(&mut paths, "a.ts"));
    assert_eq!(paths, vec!["b.ts"]);
    assert!(!retain_without_path(&mut paths, "missing.ts"));
}

#[test]
fn dedupe_paths_keeps_first_seen_order() {
    let mut paths = vec![
        "a.ts".to_string(),
        "b.ts".to_string(),
        "a.ts".to_string(),
        "c.ts".to_string(),
    ];
    dedupe_paths(&mut paths);
    assert_eq!(paths, vec!["a.ts", "b.ts", "c.ts"]);
}

#[test]
fn pin_clears_previous_exclude_for_same_path() {
    let mut context = sample_context();
    context.explicit_excludes = vec!["src/main.rs".to_string()];

    apply_pin_file_context_path(&mut context, "src/main.rs").expect("pin should succeed");

    assert_eq!(context.pinned_files, vec!["src/main.rs"]);
    assert_eq!(context.explicit_includes, vec!["src/main.rs"]);
    assert!(context.explicit_excludes.is_empty());
    assert_eq!(context.recent_files, vec!["src/main.rs"]);
}

#[test]
fn exclude_clears_previous_pin_and_include_for_same_path() {
    let mut context = sample_context();
    context.pinned_files = vec!["src/main.rs".to_string()];
    context.explicit_includes = vec!["src/main.rs".to_string()];

    apply_exclude_file_context_path(&mut context, "src/main.rs").expect("exclude should succeed");

    assert!(context.pinned_files.is_empty());
    assert!(context.explicit_includes.is_empty());
    assert_eq!(context.explicit_excludes, vec!["src/main.rs"]);
    assert_eq!(context.recent_files, vec!["src/main.rs"]);
}

#[test]
fn remove_clears_all_path_state() {
    let mut context = sample_context();
    context.pinned_files = vec!["src/main.rs".to_string()];
    context.explicit_includes = vec!["src/main.rs".to_string()];
    context.explicit_excludes = vec!["src/main.rs".to_string()];
    context.recent_files = vec!["src/main.rs".to_string()];

    apply_remove_file_context_path(&mut context, "src/main.rs").expect("remove should succeed");

    assert!(context.pinned_files.is_empty());
    assert!(context.explicit_includes.is_empty());
    assert!(context.explicit_excludes.is_empty());
    assert!(context.recent_files.is_empty());
}
