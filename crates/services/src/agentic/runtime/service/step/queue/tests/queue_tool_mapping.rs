use super::*;

#[test]
fn queue_maps_browser_click_element_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        21,
        serde_json::json!({
            "id": "btn_submit"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserClickElement {
            id,
            ids,
            delay_ms_between_ids,
            continue_with,
        } => {
            assert_eq!(id.as_deref(), Some("btn_submit"));
            assert!(ids.is_empty());
            assert!(delay_ms_between_ids.is_none());
            assert!(continue_with.is_none());
        }
        other => panic!("expected BrowserClickElement, got {:?}", other),
    }
}

#[test]
fn queue_maps_browser_click_element_batch_ids_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        22,
        serde_json::json!({
            "ids": ["checkbox_a", "checkbox_b", "btn_submit"]
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserClickElement {
            id,
            ids,
            delay_ms_between_ids,
            continue_with,
        } => {
            assert!(id.is_none());
            assert_eq!(ids, vec!["checkbox_a", "checkbox_b", "btn_submit"]);
            assert!(delay_ms_between_ids.is_none());
            assert!(continue_with.is_none());
        }
        other => panic!("expected BrowserClickElement, got {:?}", other),
    }
}

#[test]
fn queue_maps_browser_wait_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        23,
        serde_json::json!({
            "ms": 400
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserWait { ms, condition, .. } => {
            assert_eq!(ms, Some(400));
            assert!(condition.is_none());
        }
        other => panic!("expected BrowserWait, got {:?}", other),
    }
}

#[test]
fn queue_maps_browser_wait_condition_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        223,
        serde_json::json!({
            "condition": "selector_visible",
            "selector": "input[name='q']",
            "timeout_ms": 1200
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserWait {
            ms,
            condition,
            selector,
            timeout_ms,
            ..
        } => {
            assert!(ms.is_none());
            assert_eq!(condition.as_deref(), Some("selector_visible"));
            assert_eq!(selector.as_deref(), Some("input[name='q']"));
            assert_eq!(timeout_ms, Some(1200));
        }
        other => panic!("expected BrowserWait condition mode, got {:?}", other),
    }
}

#[test]
fn queue_maps_browser_wait_with_follow_up_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        224,
        serde_json::json!({
            "ms": 2000,
            "continue_with": {
                "name": "browser__click_element",
                "arguments": {
                    "id": "btn_two"
                }
            }
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserWait {
            ms, continue_with, ..
        } => {
            assert_eq!(ms, Some(2000));
            let continue_with = continue_with.expect("follow-up should be present");
            assert_eq!(continue_with.name, "browser__click_element");
            assert_eq!(continue_with.arguments["id"], "btn_two");
        }
        other => panic!("expected BrowserWait, got {:?}", other),
    }
}

#[test]
fn queue_maps_browser_find_text_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        221,
        serde_json::json!({
            "query": "weather",
            "scope": "visible",
            "scroll": true
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserFindText {
            query,
            scope,
            scroll,
        } => {
            assert_eq!(query, "weather");
            assert_eq!(scope.as_deref(), Some("visible"));
            assert!(scroll);
        }
        other => panic!("expected BrowserFindText, got {:?}", other),
    }
}

#[test]
fn queue_maps_browser_screenshot_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        222,
        serde_json::json!({
            "full_page": true
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserScreenshot { full_page } => assert!(full_page),
        other => panic!("expected BrowserScreenshot, got {:?}", other),
    }
}

#[test]
fn queue_maps_browser_upload_file_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        23,
        serde_json::json!({
            "selector": "input[type='file']",
            "paths": ["/tmp/demo.txt"]
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserUploadFile {
            selector,
            som_id,
            paths,
        } => {
            assert_eq!(selector.as_deref(), Some("input[type='file']"));
            assert!(som_id.is_none());
            assert_eq!(paths, vec!["/tmp/demo.txt".to_string()]);
        }
        other => panic!("expected BrowserUploadFile, got {:?}", other),
    }
}

#[test]
fn queue_maps_browser_upload_file_with_som_id_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        27,
        serde_json::json!({
            "som_id": 7,
            "paths": ["/tmp/demo.txt"]
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserUploadFile {
            selector,
            som_id,
            paths,
        } => {
            assert!(selector.is_none());
            assert_eq!(som_id, Some(7));
            assert_eq!(paths, vec!["/tmp/demo.txt".to_string()]);
        }
        other => panic!("expected BrowserUploadFile, got {:?}", other),
    }
}

#[test]
fn queue_maps_browser_select_dropdown_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        24,
        serde_json::json!({
            "selector": "select[name='country']",
            "value": "US"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserSelectDropdown {
            id,
            selector,
            som_id,
            value,
            label,
        } => {
            assert!(id.is_none());
            assert_eq!(selector.as_deref(), Some("select[name='country']"));
            assert!(som_id.is_none());
            assert_eq!(value.as_deref(), Some("US"));
            assert!(label.is_none());
        }
        other => panic!("expected BrowserSelectDropdown, got {:?}", other),
    }
}

#[test]
fn queue_maps_browser_select_dropdown_with_som_id_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        28,
        serde_json::json!({
            "som_id": 12,
            "label": "United States"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserSelectDropdown {
            id,
            selector,
            som_id,
            value,
            label,
        } => {
            assert!(id.is_none());
            assert!(selector.is_none());
            assert_eq!(som_id, Some(12));
            assert!(value.is_none());
            assert_eq!(label.as_deref(), Some("United States"));
        }
        other => panic!("expected BrowserSelectDropdown, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_browser_tool_name_override_for_dropdown_options() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        26,
        serde_json::json!({
            "selector": "select[name='country']",
            "__ioi_tool_name": "browser__dropdown_options"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserDropdownOptions {
            id,
            selector,
            som_id,
        } => {
            assert!(id.is_none());
            assert_eq!(selector.as_deref(), Some("select[name='country']"));
            assert!(som_id.is_none());
        }
        other => panic!("expected BrowserDropdownOptions, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_webretrieve_tool_name_override_for_media_extract_transcript() {
    let request = build_request(
        ActionTarget::WebRetrieve,
        30,
        serde_json::json!({
            "url": "https://example.com/video",
            "language": "en",
            "__ioi_tool_name": "media__extract_transcript"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::MediaExtractTranscript {
            url,
            language,
            max_chars,
        } => {
            assert_eq!(url, "https://example.com/video");
            assert_eq!(language.as_deref(), Some("en"));
            assert!(max_chars.is_none());
        }
        other => panic!("expected MediaExtractTranscript, got {:?}", other),
    }
}

#[test]
fn queue_uses_explicit_webretrieve_tool_name_override_for_media_extract_multimodal() {
    let request = build_request(
        ActionTarget::WebRetrieve,
        31,
        serde_json::json!({
            "url": "https://example.com/video",
            "language": "en",
            "frame_limit": 6,
            "__ioi_tool_name": "media__extract_multimodal_evidence"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::MediaExtractMultimodalEvidence {
            url,
            language,
            max_chars,
            frame_limit,
        } => {
            assert_eq!(url, "https://example.com/video");
            assert_eq!(language.as_deref(), Some("en"));
            assert!(max_chars.is_none());
            assert_eq!(frame_limit, Some(6));
        }
        other => panic!("expected MediaExtractMultimodalEvidence, got {:?}", other),
    }
}

#[test]
fn queue_maps_browser_dropdown_options_from_som_id_payload() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        29,
        serde_json::json!({
            "som_id": 42
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserDropdownOptions {
            id,
            selector,
            som_id,
        } => {
            assert!(id.is_none());
            assert!(selector.is_none());
            assert_eq!(som_id, Some(42));
        }
        other => panic!("expected BrowserDropdownOptions, got {:?}", other),
    }
}

#[test]
fn queue_maps_browser_select_dropdown_with_semantic_id_from_browser_interact_target() {
    let request = build_request(
        ActionTarget::BrowserInteract,
        280,
        serde_json::json!({
            "id": "inp_country",
            "label": "United States"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::BrowserSelectDropdown {
            id,
            selector,
            som_id,
            value,
            label,
        } => {
            assert_eq!(id.as_deref(), Some("inp_country"));
            assert!(selector.is_none());
            assert!(som_id.is_none());
            assert!(value.is_none());
            assert_eq!(label.as_deref(), Some("United States"));
        }
        other => panic!("expected BrowserSelectDropdown, got {:?}", other),
    }
}

#[test]
fn queue_maps_net_fetch_target_to_typed_net_fetch_tool() {
    let request = build_request(
        ActionTarget::NetFetch,
        25,
        serde_json::json!({
            "url": "https://example.com",
            "max_chars": 123
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::NetFetch { url, max_chars } => {
            assert_eq!(url, "https://example.com");
            assert_eq!(max_chars, Some(123));
        }
        other => panic!("expected NetFetch, got {:?}", other),
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
fn queue_maps_custom_os_launch_app_target() {
    let request = build_custom_request(
        "os::launch_app",
        153,
        serde_json::json!({
            "app_name": "calculator"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::OsLaunchApp { app_name } => {
            assert_eq!(app_name, "calculator");
        }
        other => panic!("expected OsLaunchApp, got {:?}", other),
    }
}

#[test]
fn queue_does_not_allow_metadata_override_for_sys_exec_target() {
    let request = build_sys_exec_request(serde_json::json!({
        "app_name": "calculator",
        "__ioi_tool_name": "os__launch_app"
    }));

    let err = queue_action_request_to_tool(&request).expect_err("expected schema error");
    assert!(err.to_string().contains("__ioi_tool_name"));
}

#[test]
fn queue_does_not_allow_metadata_to_override_non_fs_target_inference() {
    let request = build_sys_exec_request(serde_json::json!({
        "command": "echo",
        "args": ["ok"],
        "__ioi_tool_name": "os__launch_app"
    }));

    let err = queue_action_request_to_tool(&request).expect_err("expected schema error");
    assert!(err.to_string().contains("__ioi_tool_name"));
}

#[test]
fn queue_uses_explicit_sys_exec_tool_name_override_for_exec_session() {
    let request = build_sys_exec_request(serde_json::json!({
        "command": "echo",
        "args": ["ok"],
        "__ioi_tool_name": "sys__exec_session"
    }));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::SysExecSession { command, args, .. } => {
            assert_eq!(command, "echo");
            assert_eq!(args, vec!["ok".to_string()]);
        }
        other => panic!("expected SysExecSession, got {:?}", other),
    }
}

#[test]
fn queue_maps_sys_exec_session_custom_alias() {
    let request = build_custom_request(
        "sys::exec_session",
        151,
        serde_json::json!({
            "command": "bash",
            "args": ["-lc", "echo ok"]
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::SysExecSession { command, args, .. } => {
            assert_eq!(command, "bash");
            assert_eq!(args, vec!["-lc".to_string(), "echo ok".to_string()]);
        }
        other => panic!("expected SysExecSession, got {:?}", other),
    }
}

#[test]
fn queue_maps_sys_exec_session_reset_custom_alias() {
    let request = build_custom_request("sys::exec_session_reset", 152, serde_json::json!({}));

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::SysExecSessionReset {} => {}
        other => panic!("expected SysExecSessionReset, got {:?}", other),
    }
}

#[test]
fn queue_maps_math_eval_custom_alias() {
    let request = build_custom_request(
        "math::eval",
        153,
        serde_json::json!({
            "expression": "247 * 38"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::MathEval { expression } => {
            assert_eq!(expression, "247 * 38");
        }
        other => panic!("expected MathEval, got {:?}", other),
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
fn queue_uses_explicit_guiclick_tool_name_override_for_click_element() {
    let request = build_request(
        ActionTarget::GuiClick,
        32,
        serde_json::json!({
            "id": "btn_submit",
            "__ioi_tool_name": "gui__click_element"
        }),
    );

    let tool = queue_action_request_to_tool(&request).expect("queue mapping should succeed");
    match tool {
        AgentTool::GuiClickElement { id } => {
            assert_eq!(id, "btn_submit");
        }
        other => panic!("expected GuiClickElement, got {:?}", other),
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
