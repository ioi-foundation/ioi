use super::support::{
    fallback_search_summary, queue_action_request_to_tool, summarize_search_results,
};
use ioi_types::app::agentic::{AgentTool, ComputerAction};
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn build_request(target: ActionTarget, nonce: u64, args: serde_json::Value) -> ActionRequest {
    ActionRequest {
        target,
        params: serde_json::to_vec(&args).expect("params should serialize"),
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce,
    }
}

fn build_fs_read_request(args: serde_json::Value) -> ActionRequest {
    build_request(ActionTarget::FsRead, 7, args)
}

fn build_fs_write_request(args: serde_json::Value) -> ActionRequest {
    build_request(ActionTarget::FsWrite, 11, args)
}

fn build_custom_request(name: &str, nonce: u64, args: serde_json::Value) -> ActionRequest {
    build_request(ActionTarget::Custom(name.to_string()), nonce, args)
}

fn build_sys_exec_request(args: serde_json::Value) -> ActionRequest {
    build_request(ActionTarget::SysExec, 13, args)
}

#[test]
fn summary_contains_topic_and_refinement_hint() {
    let summary = summarize_search_results(
        "internet of intelligence",
        "https://duckduckgo.com/?q=internet+of+intelligence",
        "<html><body><a href=\"https://example.com/a\">A</a>\nThe Internet of Intelligence explores decentralized agent coordination.\nOpen protocols enable verifiable execution and policy enforcement.</body></html>",
    );
    assert!(summary.contains("Search summary for 'internet of intelligence'"));
    assert!(summary.contains("Source URL: https://duckduckgo.com/?q=internet+of+intelligence"));
    assert!(summary.contains("Next refinement:"));
}

#[test]
fn fallback_summary_is_deterministic() {
    let msg = fallback_search_summary(
        "internet of intelligence",
        "https://duckduckgo.com/?q=internet+of+intelligence",
    );
    assert_eq!(
        msg,
        "Searched 'internet of intelligence' at https://duckduckgo.com/?q=internet+of+intelligence, but structured extraction failed. Retry refinement if needed."
    );
}

#[test]
fn queue_maps_browser_click_element_custom_target_deterministically() {
    let request = build_custom_request(
        "browser::click_element",
        21,
        serde_json::json!({
            "id": "btn_submit"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserClickElement { id } => {
            assert_eq!(id, "btn_submit");
        }
        other => panic!("expected BrowserClickElement, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_search_from_fsread_target() {
    let request = build_fs_read_request(serde_json::json!({
        "path": "/tmp/workspace",
        "regex": "TODO",
        "file_pattern": "*.rs"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsSearch {
            path,
            regex,
            file_pattern,
        } => {
            assert_eq!(path, "/tmp/workspace");
            assert_eq!(regex, "TODO");
            assert_eq!(file_pattern.as_deref(), Some("*.rs"));
        }
        other => panic!("expected FsSearch, got {:?}", other),
    }
}

#[test]
fn queue_infers_list_directory_for_existing_directory_path() {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after unix epoch")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("ioi_queue_fs_list_{}", unique));
    fs::create_dir_all(&dir).expect("temp directory should be created");
    let request = build_fs_read_request(serde_json::json!({
        "path": dir.to_string_lossy()
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsList { path } => {
            assert_eq!(path, dir.to_string_lossy());
        }
        other => panic!("expected FsList, got {:?}", other),
    }

    let _ = fs::remove_dir_all(dir);
}

#[test]
fn queue_uses_explicit_fsread_tool_name_override() {
    let request = build_fs_read_request(serde_json::json!({
        "path": "/tmp/not-a-real-directory",
        "__ioi_tool_name": "filesystem__list_directory"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsList { path } => {
            assert_eq!(path, "/tmp/not-a-real-directory");
        }
        other => panic!("expected FsList, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_fsread_tool_name_override_for_custom_alias_target() {
    let request = build_custom_request(
        "fs::read",
        8,
        serde_json::json!({
            "path": "/tmp/not-a-real-directory",
            "__ioi_tool_name": "filesystem__list_directory"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsList { path } => {
            assert_eq!(path, "/tmp/not-a-real-directory");
        }
        other => panic!("expected FsList, got {:?}", other),
    }
}

#[test]
fn queue_rejects_incompatible_explicit_tool_name_for_target() {
    let request = build_fs_read_request(serde_json::json!({
        "path": "/tmp/demo.txt",
        "__ioi_tool_name": "filesystem__write_file"
    }));

    let err = queue_action_request_to_tool(&request)
        .expect_err("queue mapping should fail for incompatible explicit tool name");
    assert!(err.to_string().contains("incompatible"));
}

#[test]
fn queue_rejects_ambiguous_fswrite_transfer_without_explicit_tool_name() {
    let request = build_fs_write_request(serde_json::json!({
        "source_path": "/tmp/source.txt",
        "destination_path": "/tmp/destination.txt"
    }));

    let err = queue_action_request_to_tool(&request)
        .expect_err("queue mapping should fail for ambiguous transfer without explicit tool name");
    assert!(err.to_string().contains("__ioi_tool_name"));
    assert!(err.to_string().contains("filesystem__copy_path"));
}

#[test]
fn queue_rejects_ambiguous_fswrite_transfer_without_explicit_tool_name_for_custom_alias_target() {
    let request = build_custom_request(
        "fs::write",
        9,
        serde_json::json!({
            "source_path": "/tmp/source.txt",
            "destination_path": "/tmp/destination.txt"
        }),
    );

    let err = queue_action_request_to_tool(&request)
        .expect_err("queue mapping should fail for ambiguous transfer without explicit tool name");
    assert!(err.to_string().contains("__ioi_tool_name"));
    assert!(err.to_string().contains("filesystem__move_path"));
}

#[test]
fn queue_defaults_to_read_file_when_not_search_or_directory() {
    let request = build_fs_read_request(serde_json::json!({
        "path": "/tmp/not-a-real-file.txt"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsRead { path } => {
            assert_eq!(path, "/tmp/not-a-real-file.txt");
        }
        other => panic!("expected FsRead, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_patch_from_fswrite_target() {
    let request = build_fs_write_request(serde_json::json!({
        "path": "/tmp/demo.txt",
        "search": "alpha",
        "replace": "beta"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsPatch {
            path,
            search,
            replace,
        } => {
            assert_eq!(path, "/tmp/demo.txt");
            assert_eq!(search, "alpha");
            assert_eq!(replace, "beta");
        }
        other => panic!("expected FsPatch, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_delete_from_fswrite_target() {
    let request = build_fs_write_request(serde_json::json!({
        "path": "/tmp/demo.txt",
        "recursive": false,
        "ignore_missing": true
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsDelete {
            path,
            recursive,
            ignore_missing,
        } => {
            assert_eq!(path, "/tmp/demo.txt");
            assert!(!recursive);
            assert!(ignore_missing);
        }
        other => panic!("expected FsDelete, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_delete_from_fswrite_target_when_recursive() {
    let request = build_fs_write_request(serde_json::json!({
        "path": "/tmp/demo-dir",
        "recursive": true,
        "ignore_missing": false
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsDelete {
            path,
            recursive,
            ignore_missing,
        } => {
            assert_eq!(path, "/tmp/demo-dir");
            assert!(recursive);
            assert!(!ignore_missing);
        }
        other => panic!("expected FsDelete, got {:?}", other),
    }
}

#[test]
fn queue_preserves_filesystem_create_directory_from_fswrite_target() {
    let request = build_fs_write_request(serde_json::json!({
        "path": "/tmp/new-dir",
        "recursive": true
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsCreateDirectory { path, recursive } => {
            assert_eq!(path, "/tmp/new-dir");
            assert!(recursive);
        }
        other => panic!("expected FsCreateDirectory, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_fswrite_tool_name_override_for_copy_path() {
    let request = build_fs_write_request(serde_json::json!({
        "source_path": "/tmp/source.txt",
        "destination_path": "/tmp/destination.txt",
        "overwrite": true,
        "__ioi_tool_name": "filesystem__copy_path"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsCopy {
            source_path,
            destination_path,
            overwrite,
        } => {
            assert_eq!(source_path, "/tmp/source.txt");
            assert_eq!(destination_path, "/tmp/destination.txt");
            assert!(overwrite);
        }
        other => panic!("expected FsCopy, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_fswrite_tool_name_override_for_move_path() {
    let request = build_fs_write_request(serde_json::json!({
        "source_path": "/tmp/source.txt",
        "destination_path": "/tmp/destination.txt",
        "overwrite": false,
        "__ioi_tool_name": "filesystem__move_path"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsMove {
            source_path,
            destination_path,
            overwrite,
        } => {
            assert_eq!(source_path, "/tmp/source.txt");
            assert_eq!(destination_path, "/tmp/destination.txt");
            assert!(!overwrite);
        }
        other => panic!("expected FsMove, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_fswrite_tool_name_override_for_custom_alias_target() {
    let request = build_custom_request(
        "fs::write",
        17,
        serde_json::json!({
            "source_path": "/tmp/source.txt",
            "destination_path": "/tmp/destination.txt",
            "__ioi_tool_name": "filesystem__move_path"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::FsMove {
            source_path,
            destination_path,
            overwrite,
        } => {
            assert_eq!(source_path, "/tmp/source.txt");
            assert_eq!(destination_path, "/tmp/destination.txt");
            assert!(!overwrite);
        }
        other => panic!("expected FsMove, got {:?}", other),
    }
}

#[test]
fn queue_preserves_launch_app_for_sys_exec_target_with_app_name() {
    let request = build_sys_exec_request(serde_json::json!({
        "app_name": "calculator"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::OsLaunchApp { app_name } => {
            assert_eq!(app_name, "calculator");
        }
        other => panic!("expected OsLaunchApp, got {:?}", other),
    }
}

#[test]
fn queue_ignores_explicit_tool_name_metadata_for_sys_exec_target() {
    let request = build_sys_exec_request(serde_json::json!({
        "app_name": "calculator",
        "__ioi_tool_name": "os__launch_app"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::OsLaunchApp { app_name } => {
            assert_eq!(app_name, "calculator");
        }
        other => panic!("expected OsLaunchApp, got {:?}", other),
    }
}

#[test]
fn queue_does_not_allow_metadata_to_override_non_fs_target_inference() {
    let request = build_sys_exec_request(serde_json::json!({
        "command": "echo",
        "args": ["ok"],
        "__ioi_tool_name": "os__launch_app"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::SysExec { command, args, .. } => {
            assert_eq!(command, "echo");
            assert_eq!(args, vec!["ok".to_string()]);
        }
        other => panic!("expected SysExec, got {:?}", other),
    }
}

#[test]
fn queue_preserves_computer_left_click_payload_for_guiclick_target() {
    let request = build_request(
        ActionTarget::GuiClick,
        31,
        serde_json::json!({
            "action": "left_click",
            "coordinate": [120, 240]
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::Computer(ComputerAction::LeftClick { coordinate }) => {
            assert_eq!(coordinate, Some([120, 240]));
        }
        other => panic!("expected Computer LeftClick, got {:?}", other),
    }
}

#[test]
fn queue_maps_guimousemove_target_to_computer_tool() {
    let request = build_request(
        ActionTarget::GuiMouseMove,
        33,
        serde_json::json!({
            "coordinate": [55, 89]
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::Computer(ComputerAction::MouseMove { coordinate }) => {
            assert_eq!(coordinate, [55, 89]);
        }
        other => panic!("expected Computer MouseMove, got {:?}", other),
    }
}

#[test]
fn queue_maps_guiscreenshot_target_to_computer_tool() {
    let request = build_request(ActionTarget::GuiScreenshot, 35, serde_json::json!({}));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::Computer(ComputerAction::Screenshot) => {}
        other => panic!("expected Computer Screenshot, got {:?}", other),
    }
}

#[test]
fn queue_maps_custom_computer_cursor_alias_to_computer_tool() {
    let request = build_custom_request(
        "computer::cursor",
        37,
        serde_json::json!({
            "action": "cursor_position"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::Computer(ComputerAction::CursorPosition) => {}
        other => panic!("expected Computer CursorPosition, got {:?}", other),
    }
}
