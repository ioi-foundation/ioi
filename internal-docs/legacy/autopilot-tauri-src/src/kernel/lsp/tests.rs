use super::{
    capability_registry_entry, discover_server_for_path, parse_code_action_result,
    parse_location_result, snapshot_workspace_file, WorkspaceLspServerKind,
};
use serde_json::json;
use std::path::Path;

#[test]
fn capability_entry_is_stable() {
    let entry = capability_registry_entry();
    assert_eq!(entry.entry_id, "workspace_service:lsp");
    assert_eq!(entry.kind, "workspace_service");
}

#[test]
fn rust_server_discovery_prefers_rust_files() {
    let workspace_root = Path::new("/tmp");
    let file = Path::new("/tmp/example.rs");
    let discovered = discover_server_for_path(workspace_root, file);
    if let Some(discovered) = discovered {
        match discovered.kind {
            WorkspaceLspServerKind::RustAnalyzer => {}
            WorkspaceLspServerKind::TypeScriptLanguageServer => {
                panic!("Rust files should not map to TypeScript language servers")
            }
        }
    }
}

#[test]
fn parse_location_result_accepts_single_location() {
    let root = std::env::current_dir().expect("cwd");
    let file_uri = url::Url::from_file_path(root.join("Cargo.toml"))
        .expect("uri")
        .to_string();
    let value = json!({
        "uri": file_uri,
        "range": {
            "start": { "line": 1, "character": 2 },
            "end": { "line": 1, "character": 5 }
        }
    });
    let locations = parse_location_result(&root, value);
    assert_eq!(locations.len(), 1);
    assert_eq!(locations[0].line, 2);
    assert_eq!(locations[0].column, 3);
}

#[test]
fn parse_code_action_result_extracts_workspace_edits() {
    let root = std::env::current_dir().expect("cwd");
    let cargo_uri = url::Url::from_file_path(root.join("Cargo.toml"))
        .expect("cargo uri")
        .to_string();
    let readme_uri = url::Url::from_file_path(root.join("README.md"))
        .expect("readme uri")
        .to_string();
    let actions = parse_code_action_result(
        &root,
        json!([
            {
                "title": "Apply quick fix",
                "kind": "quickfix",
                "isPreferred": true,
                "edit": {
                    "changes": {
                        (cargo_uri.clone()): [
                            {
                                "range": {
                                    "start": { "line": 0, "character": 0 },
                                    "end": { "line": 0, "character": 5 }
                                },
                                "newText": "fixed"
                            }
                        ]
                    },
                    "documentChanges": [
                        {
                            "textDocument": { "uri": readme_uri.clone(), "version": 1 },
                            "edits": [
                                {
                                    "range": {
                                        "start": { "line": 1, "character": 0 },
                                        "end": { "line": 1, "character": 4 }
                                    },
                                    "newText": "docs"
                                }
                            ]
                        }
                    ]
                }
            },
            {
                "title": "Blocked quick fix",
                "kind": "quickfix",
                "disabled": { "reason": "Server cannot apply this yet." }
            }
        ]),
    );
    assert_eq!(actions.len(), 2);
    assert_eq!(actions[0].title, "Apply quick fix");
    assert!(actions[0].is_preferred);
    assert_eq!(actions[0].edits.len(), 2);
    assert_eq!(actions[0].edits[0].path, "Cargo.toml");
    assert_eq!(actions[0].edits[0].new_text, "fixed");
    assert_eq!(actions[0].edits[1].path, "README.md");
    assert_eq!(actions[0].edits[1].new_text, "docs");
    assert_eq!(
        actions[1].disabled_reason.as_deref(),
        Some("Server cannot apply this yet.")
    );
}

#[test]
fn rust_analyzer_snapshot_smoke_test_if_available() {
    let workspace_root = std::env::current_dir().expect("cwd");
    let file = workspace_root.join("apps/autopilot/src-tauri/src/kernel/capabilities.rs");
    if !file.exists() {
        return;
    }
    let Some(server) = discover_server_for_path(&workspace_root, &file) else {
        return;
    };
    match server.kind {
        WorkspaceLspServerKind::RustAnalyzer => {}
        WorkspaceLspServerKind::TypeScriptLanguageServer => return,
    }
    let snapshot = snapshot_workspace_file(
        &workspace_root,
        "apps/autopilot/src-tauri/src/kernel/capabilities.rs",
        None,
    )
    .expect("snapshot");
    assert_eq!(snapshot.language_id, "rust");
}
