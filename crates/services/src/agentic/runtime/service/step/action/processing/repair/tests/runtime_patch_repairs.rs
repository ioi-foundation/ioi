use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_upconverts_runtime_line_edit_to_full_write() {
    let runtime = Arc::new(RepairRecordingRuntime::default());
    runtime
        .outputs
        .lock()
        .expect("outputs mutex poisoned")
        .push(Ok(
            r#"{"name":"filesystem__edit_line","arguments":{"path":"/tmp/wrong/path_utils.py","line_number":6,"content":"return raw_path.replace(\"\\\\\", \"/\").strip()","text":"return raw_path.replace(\"\\\\\", \"/\").strip()"}} "#
                .trim()
                .as_bytes()
                .to_vec(),
        ));
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime.clone(),
    );

    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    let original = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
    );
    fs::write(&path_utils, original).expect("write fixture source");

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x6a; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    record_targeted_check_failure(&mut worker_state);
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
        )
        .expect("insert worker state");
    persist_worker_assignment(
        &mut state,
        session_id,
        &patch_assignment_with_allowed_tools(vec![
            "filesystem__write_file",
            "filesystem__edit_line",
            "sys__exec_session",
            "agent__complete",
        ]),
    )
    .expect("persist worker assignment");

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        "I will update the function using filesystem__edit_line after the failing test.",
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    match repair.repaired_tool.expect("expected repaired tool") {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            assert_eq!(path, "path_utils.py");
            assert_eq!(line_number, None);
            assert!(content.contains("return raw_path.replace(\"\\\\\", \"/\").strip()"));
            assert!(!content.contains("return raw_path.strip().replace(\"\\\\\", \"/\")"));
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| { check == "invalid_tool_call_repair_runtime_line_edit_upconverted=true" }));
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "invalid_tool_call_repair_runtime=fast"));
    assert_eq!(
        runtime
            .seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .len(),
        1
    );
}

#[test]
fn patch_build_verify_runtime_line_edit_upconvert_prefers_retained_raw_output() {
    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    let original = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
    );
    fs::write(&path_utils, original).expect("write fixture source");

    let session_id = [0x6d; 32];
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();

    let repaired_tool = upconvert_patch_build_verify_runtime_line_edit_repair(
        &worker_state,
        Some(&patch_assignment_with_allowed_tools(vec![
            "filesystem__write_file",
            "filesystem__edit_line",
            "sys__exec_session",
            "agent__complete",
        ])),
        concat!(
            "portun normalize_fixture_path to convert backslashes to forward slashes, collapse duplicate separators, and preserve a leading ./ or /. The current implementation is:\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            " return raw_path.strip().replace(\"\\\\\", \"/\")\n",
            "```\n\n",
            "To achieve the goal, we need to update this function. Let's modify it to handle backslashes and duplicate separators correctly.\n\n",
            "First, let's edit line 8 of `path_utils.py`:\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            " return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")\n",
            "```\n\n",
            "Now, let's use the `filesystem__edit_line` tool to make this change.\n"
        ),
        AgentTool::FsWrite {
            path: "/tmp/wrong/path_utils.py".to_string(),
            content: "First, let's edit line 8 of path_utils.py".to_string(),
            line_number: Some(8),
        },
        &mut Vec::new(),
    );

    match repaired_tool {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            assert_eq!(path, "path_utils.py");
            assert_eq!(line_number, None);
            assert!(content.contains("replace(\"//\", \"/\")"));
            assert!(content.contains("lstrip(\"./\")"));
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }

    let mut verification_checks = Vec::new();
    let _ = upconvert_patch_build_verify_runtime_line_edit_repair(
        &worker_state,
        Some(&patch_assignment_with_allowed_tools(vec![
            "filesystem__write_file",
            "filesystem__edit_line",
            "sys__exec_session",
            "agent__complete",
        ])),
        concat!(
            "portun normalize_fixture_path to convert backslashes to forward slashes, collapse duplicate separators, and preserve a leading ./ or /. The current implementation is:\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            " return raw_path.strip().replace(\"\\\\\", \"/\")\n",
            "```\n\n",
            "To achieve the goal, we need to update this function. Let's modify it to handle backslashes and duplicate separators correctly.\n\n",
            "First, let's edit line 8 of `path_utils.py`:\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            " return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")\n",
            "```\n\n",
            "Now, let's use the `filesystem__edit_line` tool to make this change.\n"
        ),
        AgentTool::FsWrite {
            path: "/tmp/wrong/path_utils.py".to_string(),
            content: "First, let's edit line 8 of path_utils.py".to_string(),
            line_number: Some(8),
        },
        &mut verification_checks,
    );
    assert!(verification_checks
        .iter()
        .any(|check| { check == "invalid_tool_call_repair_runtime_line_edit_upconverted=true" }));
    assert!(verification_checks
        .iter()
        .any(|check| { check == "invalid_tool_call_repair_runtime_line_edit_source=raw_output" }));
}

#[test]
fn patch_build_verify_runtime_patch_miss_repair_recovers_full_write_from_patch_replace_block() {
    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    let original = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
    );
    fs::write(&path_utils, original).expect("write fixture source");

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x6e; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
        )
        .expect("insert worker state");
    persist_worker_assignment(&mut state, session_id, &patch_assignment())
        .expect("persist worker assignment");

    let mut verification_checks = Vec::new();
    let repair = attempt_patch_build_verify_runtime_patch_miss_repair(
        &state,
        &worker_state,
        session_id,
        "filesystem__patch",
        Some(
            "ERROR_CLASS=NoEffectAfterAction Patch failed for path_utils.py: search block not found in file.",
        ),
        r#"{"name":"filesystem__patch","arguments":{"path":"path_utils.py","search":"return raw_path.strip().replace(\"\\\\\", \"/\")","replace":"return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\")"}}"#,
        &mut verification_checks,
    )
    .expect("repair should be synthesized");

    match repair {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            assert_eq!(path, "path_utils.py");
            assert_eq!(line_number, None);
            assert!(content.contains("replace(\"//\", \"/\")"));
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
    assert!(verification_checks
        .iter()
        .any(|check| { check == "runtime_patch_miss_repair_deterministic_recovery=full_write" }));
}

#[test]
fn patch_build_verify_runtime_patch_miss_repair_recovers_full_write_from_retained_trace_payload() {
    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    let original = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
    );
    fs::write(&path_utils, original).expect("write fixture source");

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x74; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
        )
        .expect("insert worker state");
    persist_worker_assignment(
        &mut state,
        session_id,
        &patch_assignment_with_path_parity_goal(),
    )
    .expect("persist worker assignment");

    let mut verification_checks = Vec::new();
    let repair = attempt_patch_build_verify_runtime_patch_miss_repair(
        &state,
        &worker_state,
        session_id,
        "filesystem__patch",
        Some(
            "ERROR_CLASS=NoEffectAfterAction Patch failed for path_utils.py: search block not found in file.",
        ),
        r#"{"name":"filesystem__patch","arguments":{"path":"path_utils.py","replace":"return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")","search":"return raw_path.strip().replace\\(\\\", \\/\\).replace\\(\\/\\/\\, \\/\\).lstrip\\(\\.\\/\\)"}}"#,
        &mut verification_checks,
    )
    .expect("repair should be synthesized");

    match repair {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            assert_eq!(path, "path_utils.py");
            assert_eq!(line_number, None);
            assert!(
                content.contains("while \"//\" in normalized"),
                "content was: {content}"
            );
            assert!(
                content.contains("prefix = \"./\""),
                "content was: {content}"
            );
            assert!(
                !content.contains("lstrip(\"./\")"),
                "content was: {content}"
            );
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
    assert!(verification_checks.iter().any(|check| {
        check == "runtime_patch_miss_repair_deterministic_recovery=goal_constrained_snapshot_write"
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_post_command_edit_rewrites_goal_violating_direct_patch_before_execution(
) {
    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    let original = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
    );
    fs::write(&path_utils, original).expect("write fixture source");

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x83; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    record_targeted_check_failure(&mut worker_state);
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
        )
        .expect("insert worker state");
    persist_worker_assignment(
        &mut state,
        session_id,
        &patch_assignment_with_path_parity_goal(),
    )
    .expect("persist worker assignment");

    let tool = AgentTool::FsPatch {
        path: path_utils.to_string_lossy().to_string(),
        replace:
            "def normalize_fixture_path(path): return path.replace('\\\\', '/').replace('//', '/').lstrip('./')"
                .to_string(),
        search:
            "def normalize_fixture_path(path): return path.replace('\\\\', '/').replace('//', '/).lstrip('./'"
                .to_string(),
    };
    let mut verification_checks = Vec::new();

    let rewritten = super::maybe_rewrite_patch_build_verify_post_command_edit(
        &state,
        &worker_state,
        session_id,
        &tool,
        &mut verification_checks,
    )
    .await
    .expect("rewrite check should succeed")
    .expect("expected direct patch rewrite");

    match rewritten {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            assert_eq!(path, path_utils.to_string_lossy());
            assert_eq!(line_number, None);
            assert!(
                content.contains("def normalize_fixture_path(raw_path: str) -> str"),
                "content was: {content}"
            );
            assert!(
                content.contains("while \"//\" in normalized"),
                "content was: {content}"
            );
            assert!(
                content.contains("prefix = \"./\""),
                "content was: {content}"
            );
            assert!(
                !content.contains("lstrip(\"./\")"),
                "content was: {content}"
            );
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
    assert!(verification_checks
        .iter()
        .any(|check| { check == "patch_build_verify_direct_edit_projection_missing=true" }));
    assert!(verification_checks
        .iter()
        .any(|check| { check == "patch_build_verify_direct_edit_rewritten=true" }));
    assert!(verification_checks.iter().any(|check| {
        check == "patch_build_verify_direct_edit_rewrite_source=goal_constrained_snapshot"
    }));
}

#[test]
fn patch_build_verify_primary_patch_file_prefers_explicit_absolute_path_from_raw_output() {
    let assignment = patch_assignment();
    let explicit_path = "/tmp/ioi-coding-fixture-123/path-normalizer-fixture/path_utils.py";
    let raw_tool_output = format!(
        r#"{{"name":"filesystem__patch","arguments":{{"path":"{explicit_path}","search":"return raw_path.strip().replace(\"\\\\\", \"/\")","replace":"return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\")"}}}}"#
    );

    let selected = super::patch_build_verify_primary_patch_file(&assignment, &raw_tool_output)
        .expect("expected target path");

    assert_eq!(selected, explicit_path);
}

#[test]
fn patch_build_verify_runtime_patch_miss_repair_uses_explicit_absolute_path_when_cwd_differs() {
    let repo = tempdir().expect("tempdir should succeed");
    let unrelated = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    let original = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
    );
    fs::write(&path_utils, original).expect("write fixture source");

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x7a; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = unrelated.path().to_string_lossy().to_string();
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
        )
        .expect("insert worker state");
    persist_worker_assignment(&mut state, session_id, &patch_assignment())
        .expect("persist worker assignment");

    let mut verification_checks = Vec::new();
    let repair = attempt_patch_build_verify_runtime_patch_miss_repair(
        &state,
        &worker_state,
        session_id,
        "filesystem__patch",
        Some(
            "ERROR_CLASS=NoEffectAfterAction Patch failed for path_utils.py: search block not found in file.",
        ),
        format!(
            r#"{{"name":"filesystem__patch","arguments":{{"path":"{}","replace":"return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")","search":"return raw_path.strip().replace\\(\\\", \\/\\).replace\\(\\/\\/\\, \\/\\).lstrip\\(\\.\\/\\)"}}}}"#,
            path_utils.display()
        )
        .as_str(),
        &mut verification_checks,
    )
    .expect("repair should be synthesized");

    match repair {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            assert_eq!(path, path_utils.to_string_lossy());
            assert_eq!(line_number, None);
            assert!(content.contains("replace(\"//\", \"/\")"));
            assert!(content.contains("lstrip(\"./\")"));
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
    assert!(verification_checks
        .iter()
        .any(|check| { check == "runtime_patch_miss_repair_deterministic_recovery=full_write" }));
}

#[test]
fn updated_python_block_candidate_expands_inline_function_against_single_line_current_block() {
    let current_block = concat!(
        "def normalize_fixture_path(raw_path: str) -> str: ",
        "return raw_path.strip().replace(\"\\\\\", \"/\")"
    );

    let updated_block = updated_python_block_candidate_from_raw_output(
        current_block,
        concat!(
            "The corrected implementation is ",
            "normalize_fixture_path(raw_path: str) -> str: ",
            "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\" ",
            "return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\")"
        ),
    )
    .expect("inline function candidate should be recovered");

    assert!(updated_block.starts_with("def normalize_fixture_path"));
    assert!(updated_block.contains("\n    \"\"\"Normalize a repo-relative path"));
    assert!(updated_block
        .contains("\n    return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\")"));
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_falls_back_to_full_write_without_patch_tool() {
    let runtime = Arc::new(RepairRecordingRuntime::default());
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime.clone(),
    );

    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    let original = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
    );
    fs::write(&path_utils, original).expect("write fixture source");

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x67; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    record_targeted_check_failure(&mut worker_state);
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
        )
        .expect("insert worker state");
    persist_worker_assignment(
        &mut state,
        session_id,
        &patch_assignment_with_allowed_tools(vec![
            "filesystem__write_file",
            "filesystem__edit_line",
            "sys__exec_session",
            "agent__complete",
        ]),
    )
    .expect("persist worker assignment");

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        concat!(
            "Current implementation:\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n",
            "```\n\n",
            "Updated implementation:\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"/\").lstrip(\"./\")\n",
            "```\n"
        ),
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    match repair.repaired_tool.expect("expected repaired tool") {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            assert_eq!(path, "path_utils.py");
            assert_eq!(line_number, None);
            assert!(content.contains("replace(\"//\", \"/\")"));
            assert!(content.contains("lstrip(\"./\")"));
            assert!(!content.contains("strip().replace(\"\\\\\", \"/\")"));
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_recovery=code_block_write"
    }));
    assert_eq!(
        runtime
            .seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .len(),
        0
    );
}
