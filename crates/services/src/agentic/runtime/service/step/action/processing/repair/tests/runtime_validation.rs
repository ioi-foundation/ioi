use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_prefers_runtime_edit_after_command_failure() {
    let fast_runtime = Arc::new(RepairRecordingRuntime::default());
    fast_runtime
        .outputs
        .lock()
        .expect("outputs mutex poisoned")
        .push(Err(VmError::HostError("fast repair refused".to_string())));
    let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
    reasoning_runtime
        .outputs
        .lock()
        .expect("outputs mutex poisoned")
        .push(Ok(
            br#"{"name":"filesystem__write_file","arguments":{"path":"path_utils.py","content":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    prefix = \"\"\n    if raw_path.startswith(\"./\"):\n        prefix = \"./\"\n        raw_path = raw_path[2:]\n    elif raw_path.startswith(\"/\"):\n        prefix = \"/\"\n        raw_path = raw_path[1:]\n    normalized = raw_path.replace(\"\\\\\", \"/\")\n    while \"//\" in normalized:\n        normalized = normalized.replace(\"//\", \"/\")\n    return prefix + normalized"}}"#
                .to_vec(),
        ));
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        fast_runtime.clone(),
        reasoning_runtime.clone(),
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
    let session_id = [0x69; 32];
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

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        concat!(
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
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot"
    }));
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
    }));
    assert_eq!(
        fast_runtime
            .seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .len(),
        0
    );
    assert_eq!(
        reasoning_runtime
            .seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .len(),
        0
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_rejects_syntax_invalid_fast_runtime_write_before_reasoning(
) {
    let fast_runtime = Arc::new(RepairRecordingRuntime::default());
    fast_runtime
        .outputs
        .lock()
        .expect("outputs mutex poisoned")
        .push(Ok(
            br#"{"name":"filesystem__write_file","arguments":{"path":"path_utils.py","content":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./)\n"}}"#
                .to_vec(),
        ));
    let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
    reasoning_runtime
        .outputs
        .lock()
        .expect("outputs mutex poisoned")
        .push(Ok(
            br#"{"name":"filesystem__write_file","arguments":{"path":"path_utils.py","content":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    prefix = \"\"\n    if raw_path.startswith(\"./\"):\n        prefix = \"./\"\n        raw_path = raw_path[2:]\n    elif raw_path.startswith(\"/\"):\n        prefix = \"/\"\n        raw_path = raw_path[1:]\n    normalized = raw_path.replace(\"\\\\\", \"/\")\n    while \"//\" in normalized:\n        normalized = normalized.replace(\"//\", \"/\")\n    return prefix + normalized"}}"#
                .to_vec(),
        ));
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        fast_runtime.clone(),
        reasoning_runtime.clone(),
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
        &patch_assignment_with_path_parity_goal(),
    )
    .expect("persist worker assignment");

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        "I will fix the malformed tool call by updating path_utils.py after the failing tests.",
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
            assert!(
                content.contains("while \"//\" in normalized"),
                "content was: {content}"
            );
            assert!(
                content.contains("prefix = \"./\""),
                "content was: {content}"
            );
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot"
    }));
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
    }));
    assert!(fast_runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned")
        .is_empty());
    assert_eq!(
        reasoning_runtime
            .seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .len(),
        0
    );
}

#[test]
fn patch_build_verify_runtime_goal_constraints_reject_prefix_stripping_single_pass_collapse() {
    let assignment = patch_assignment_with_path_parity_goal();
    let content = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"/\").lstrip(\"./\")\n"
    );
    let mut verification_checks = Vec::new();

    let failure = super::validate_patch_build_verify_runtime_goal_constraints(
        &assignment,
        content,
        &mut verification_checks,
        "invalid_tool_call_repair",
        "fast",
    );

    assert_eq!(failure.as_deref(), Some("fast:goal_path_prefix_violation"));
    assert!(verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_runtime_fast_goal_path_prefix_violation=true"
    }));
}

#[test]
fn patch_build_verify_runtime_goal_constraints_reject_reverse_separator_direction() {
    let assignment = patch_assignment_with_path_parity_goal();
    let content = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    prefix = \"\"\n",
        "    if raw_path.startswith(\"./\"):\n",
        "        prefix = \"./\"\n",
        "        raw_path = raw_path[2:]\n",
        "    elif raw_path.startswith(\"/\"):\n",
        "        prefix = \"/\"\n",
        "        raw_path = raw_path[1:]\n",
        "    normalized = raw_path.replace(\"/\", \"\\\\\")\n",
        "    while \"\\\\\" in normalized:\n",
        "        normalized = normalized.replace(\"\\\\\", \"\\\\\")\n",
        "    return prefix + normalized\n"
    );
    let mut verification_checks = Vec::new();

    let failure = super::validate_patch_build_verify_runtime_goal_constraints(
        &assignment,
        content,
        &mut verification_checks,
        "invalid_tool_call_repair",
        "fast",
    );

    assert_eq!(
        failure.as_deref(),
        Some("fast:goal_separator_direction_violation")
    );
    assert!(verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_runtime_fast_goal_separator_direction_violation=true"
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_runtime_edit_repair_rejects_out_of_range_line_edit_after_command_failure(
) {
    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    fs::write(
        &path_utils,
        concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        ),
    )
    .expect("write fixture source");

    let mut worker_state = build_worker_state([0x73; 32]);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    record_targeted_check_failure(&mut worker_state);

    let repaired_tool = AgentTool::FsWrite {
        path: "path_utils.py".to_string(),
        content: "return raw_path.replace(\"\\\\\", \"/\")".to_string(),
        line_number: Some(12),
    };
    let mut verification_checks = Vec::new();

    let failure = super::validate_patch_build_verify_runtime_edit_repair(
        &worker_state,
        Some(&patch_assignment()),
        "I will update the function using filesystem__edit_line.",
        &repaired_tool,
        &mut verification_checks,
        "invalid_tool_call_repair",
        "fast_retry",
    )
    .await
    .expect("validation should succeed");

    assert_eq!(
        failure.as_deref(),
        Some("fast_retry:line_number_out_of_range")
    );
    assert!(verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_runtime_fast_retry_line_number_out_of_range=true"
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_runtime_edit_repair_rejects_line_edit_without_python_context_after_command_failure(
) {
    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    fs::write(
        &path_utils,
        "return raw_path.strip().replace('\\\\', '/').replace('//', '/').strip()\n",
    )
    .expect("write corrupted fixture source");

    let mut worker_state = build_worker_state([0x74; 32]);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    record_targeted_check_failure(&mut worker_state);

    let repaired_tool = AgentTool::FsWrite {
        path: "path_utils.py".to_string(),
        content: "return raw_path.strip().replace('\\\\', '/').replace('//', '/').strip()"
            .to_string(),
        line_number: Some(1),
    };
    let mut verification_checks = Vec::new();

    let failure = super::validate_patch_build_verify_runtime_edit_repair(
        &worker_state,
        Some(&patch_assignment()),
        "I will rerun the focused verification command now.",
        &repaired_tool,
        &mut verification_checks,
        "invalid_tool_call_repair",
        "fast_retry",
    )
    .await
    .expect("validation should succeed");

    assert_eq!(
        failure.as_deref(),
        Some("fast_retry:line_edit_missing_python_context")
    );
    assert!(verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_runtime_fast_retry_line_edit_missing_python_context=true"
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_runtime_edit_repair_rejects_multiline_line_edit_after_command_failure()
{
    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    fs::write(
        &path_utils,
        concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        ),
    )
    .expect("write fixture source");

    let mut worker_state = build_worker_state([0x75; 32]);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    record_targeted_check_failure(&mut worker_state);

    let repaired_tool = AgentTool::FsWrite {
        path: "path_utils.py".to_string(),
        content: concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    prefix = \"\"\n",
            "    return prefix + raw_path.replace(\"\\\\\", \"/\")\n"
        )
        .to_string(),
        line_number: Some(1),
    };
    let mut verification_checks = Vec::new();

    let failure = super::validate_patch_build_verify_runtime_edit_repair(
        &worker_state,
        Some(&patch_assignment()),
        "I will update the function before rerunning tests.",
        &repaired_tool,
        &mut verification_checks,
        "invalid_tool_call_repair",
        "fast_retry",
    )
    .await
    .expect("validation should succeed");

    assert_eq!(
        failure.as_deref(),
        Some("fast_retry:line_edit_requires_full_write")
    );
    assert!(verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_runtime_fast_retry_line_edit_requires_full_write=true"
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_retries_same_runtime_with_edit_only_tools_after_post_command_reread_rejection(
) {
    let runtime = Arc::new(RepairRecordingRuntime::default());
    runtime
        .outputs
        .lock()
        .expect("outputs mutex poisoned")
        .push(Ok(
            br#"{"name":"filesystem__read_file","arguments":{"path":"path_utils.py"}}"#.to_vec(),
        ));
    runtime
        .outputs
        .lock()
        .expect("outputs mutex poisoned")
        .push(Ok(
            br#"{"name":"filesystem__write_file","arguments":{"path":"path_utils.py","content":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    prefix = \"\"\n    if raw_path.startswith(\"./\"):\n        prefix = \"./\"\n        raw_path = raw_path[2:]\n    elif raw_path.startswith(\"/\"):\n        prefix = \"/\"\n        raw_path = raw_path[1:]\n    normalized = raw_path.replace(\"\\\\\", \"/\")\n    while \"//\" in normalized:\n        normalized = normalized.replace(\"//\", \"/\")\n    return prefix + normalized"}}"#
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
    let session_id = [0x6b; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    record_targeted_check_failure(&mut worker_state);
    record_execution_evidence_with_value(
        &mut worker_state.tool_execution_log,
        "workspace_read_observed",
        "step=2;tool=filesystem__read_file;path=path_utils.py".to_string(),
    );
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

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        concat!(
            "portun normalize_fixture_path(raw_path: str) -> str: ",
            "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\" ",
            "return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")\n\n",
            "I will use `filesystem__edit_line` to update the `normalize_fixture_path` ",
            "function in `path_utils.py` as described. This approach ensures that ",
            "backslashes are converted to forward slashes, duplicate separators are ",
            "collapsed, and leading `./` or `/` is preserved.\n"
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
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot"
    }));
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
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

#[test]
fn patch_build_verify_redundant_refresh_read_rewrites_post_command_reread_to_goal_snapshot_write() {
    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    let original = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
    );
    fs::write(&path_utils, original).expect("write fixture source");

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x81; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    record_targeted_check_failure(&mut worker_state);
    record_execution_evidence_with_value(
        &mut worker_state.tool_execution_log,
        "workspace_read_observed",
        format!(
            "step=3;tool=filesystem__read_file;path={}",
            path_utils.display()
        ),
    );
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
    let rewritten = maybe_rewrite_patch_build_verify_redundant_refresh_read(
        &state,
        &worker_state,
        session_id,
        &AgentTool::FsRead {
            path: path_utils.to_string_lossy().to_string(),
        },
        &mut verification_checks,
    )
    .expect("expected redundant reread rewrite");

    match rewritten {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            assert_eq!(path, path_utils.to_string_lossy());
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

    assert!(verification_checks
        .iter()
        .any(|check| { check == "patch_build_verify_redundant_refresh_read_rewritten=true" }));
    assert!(verification_checks.iter().any(|check| {
        check
            == "patch_build_verify_redundant_refresh_read_rewrite_source=goal_constrained_snapshot"
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_retries_same_runtime_with_edit_only_tools_after_runtime_failure(
) {
    let runtime = Arc::new(RepairRecordingRuntime::default());
    runtime
        .outputs
        .lock()
        .expect("outputs mutex poisoned")
        .push(Err(VmError::HostError(
            "simulated runtime failure".to_string(),
        )));
    runtime
        .outputs
        .lock()
        .expect("outputs mutex poisoned")
        .push(Ok(
            br#"{"name":"filesystem__write_file","arguments":{"path":"path_utils.py","content":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    prefix = \"\"\n    if raw_path.startswith(\"./\"):\n        prefix = \"./\"\n        raw_path = raw_path[2:]\n    elif raw_path.startswith(\"/\"):\n        prefix = \"/\"\n        raw_path = raw_path[1:]\n    normalized = raw_path.replace(\"\\\\\", \"/\")\n    while \"//\" in normalized:\n        normalized = normalized.replace(\"//\", \"/\")\n    return prefix + normalized"}}"#
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
    let session_id = [0x6d; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    record_targeted_check_failure(&mut worker_state);
    record_execution_evidence_with_value(
        &mut worker_state.tool_execution_log,
        "workspace_read_observed",
        "step=2;tool=filesystem__read_file;path=path_utils.py".to_string(),
    );
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

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        concat!(
            "portun normalize_fixture_path(raw_path: str) -> str: ",
            "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\" ",
            "return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")\n\n",
            "I will use `filesystem__edit_line` to update the `normalize_fixture_path` ",
            "function in `path_utils.py` as described.\n"
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
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot"
    }));
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
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

#[tokio::test(flavor = "multi_thread")]
async fn invalid_tool_repair_prefers_fast_runtime_before_reasoning() {
    let fast_runtime = Arc::new(RepairRecordingRuntime::default());
    fast_runtime
        .outputs
        .lock()
        .expect("outputs mutex poisoned")
        .push(Ok(
            br#"{"name":"filesystem__patch","arguments":{"path":"path_utils.py","search":"def normalize_fixture_path(raw_path: str) -> str:\n    return raw_path","replace":"def normalize_fixture_path(raw_path: str) -> str:\n    return raw_path.strip().replace(\"\\\\\", \"/\")"}}"#
                .to_vec(),
        ));
    let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        fast_runtime.clone(),
        reasoning_runtime.clone(),
    );

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x33; 32];
    let key = get_state_key(&session_id);
    let worker_state = build_worker_state(session_id);
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
        )
        .expect("insert worker state");
    persist_worker_assignment(&mut state, session_id, &patch_assignment())
        .expect("persist worker assignment");

    let mut worker_state = worker_state;
    worker_state
        .command_history
        .push_back(crate::agentic::runtime::types::CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 1,
            stdout: String::new(),
            stderr: String::new(),
            timestamp_ms: 1,
            step_index: 0,
        });
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&worker_state).expect("encode updated worker state"),
        )
        .expect("update worker state");

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        "portun normalize_fixture_path(raw_path: str) -> str: return raw_path.strip().replace(\"\\\\\", \"/\")",
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    assert_eq!(
        repair
            .repaired_tool
            .unwrap_or_else(|| {
                panic!(
                    "expected repaired tool; checks={:?}",
                    repair.verification_checks
                )
            })
            .name_string(),
        "file__edit"
    );
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "invalid_tool_call_repair_runtime=fast"));
    assert_eq!(
        fast_runtime
            .seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .len(),
        1
    );
    assert_eq!(
        reasoning_runtime
            .seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .len(),
        0
    );
}
