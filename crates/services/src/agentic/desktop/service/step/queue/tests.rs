use super::support::{
    fallback_search_summary, queue_action_request_to_tool, summarize_search_results,
};
use ioi_types::app::agentic::AgentTool;
use ioi_types::app::{ActionContext, ActionRequest, ActionTarget};
use std::fs;
use std::time::{SystemTime, UNIX_EPOCH};

fn build_fs_read_request(args: serde_json::Value) -> ActionRequest {
    ActionRequest {
        target: ActionTarget::FsRead,
        params: serde_json::to_vec(&args).expect("params should serialize"),
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 7,
    }
}

fn build_fs_write_request(args: serde_json::Value) -> ActionRequest {
    ActionRequest {
        target: ActionTarget::FsWrite,
        params: serde_json::to_vec(&args).expect("params should serialize"),
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 11,
    }
}

fn build_sys_exec_request(args: serde_json::Value) -> ActionRequest {
    ActionRequest {
        target: ActionTarget::SysExec,
        params: serde_json::to_vec(&args).expect("params should serialize"),
        context: ActionContext {
            agent_id: "desktop_agent".to_string(),
            session_id: None,
            window_id: None,
        },
        nonce: 13,
    }
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
