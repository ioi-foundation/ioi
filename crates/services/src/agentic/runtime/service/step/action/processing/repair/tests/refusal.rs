use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn refusal_repair_synthesizes_targeted_exec_before_pause() {
    let fast_runtime = Arc::new(RepairRecordingRuntime::default());
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
    let session_id = [0x66; 32];
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

    let repair = attempt_refusal_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        "Empty content (reason: stop)",
    )
    .await
    .expect("refusal repair should succeed");

    match repair.repaired_tool.expect("expected repaired tool") {
        AgentTool::SysExecSession {
            command,
            args,
            stdin,
        } => {
            assert_eq!(command, "bash");
            assert_eq!(
                args,
                vec![
                    "-lc".to_string(),
                    "python3 -m unittest tests.test_path_utils -v".to_string()
                ]
            );
            assert_eq!(stdin, None);
        }
        other => panic!("expected sys__exec_session, got {:?}", other),
    }
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "refusal_repair_succeeded=true"));
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_source=refusal_empty_content"
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
async fn refusal_repair_bootstraps_targeted_exec_on_initial_empty_stop() {
    let fast_runtime = Arc::new(RepairRecordingRuntime::default());
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
    let session_id = [0x69; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.recent_actions.clear();
    worker_state.consecutive_failures = 0;
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
        )
        .expect("insert worker state");
    persist_worker_assignment(&mut state, session_id, &patch_assignment())
        .expect("persist worker assignment");

    let repair = attempt_refusal_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        "Empty content (reason: stop)",
    )
    .await
    .expect("refusal repair should succeed");

    match repair.repaired_tool.expect("expected repaired tool") {
        AgentTool::SysExecSession {
            command,
            args,
            stdin,
        } => {
            assert_eq!(command, "bash");
            assert_eq!(
                args,
                vec![
                    "-lc".to_string(),
                    "python3 -m unittest tests.test_path_utils -v".to_string()
                ]
            );
            assert_eq!(stdin, None);
        }
        other => panic!("expected sys__exec_session, got {:?}", other),
    }
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "refusal_repair_succeeded=true"));
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_source=refusal_empty_content_bootstrap"
    }));
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| { check == "invalid_tool_call_repair_targeted_command_bootstrap=initial" }));
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
async fn refusal_repair_does_not_replay_targeted_exec_after_command_history() {
    let fast_runtime = Arc::new(RepairRecordingRuntime::default());
    let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        fast_runtime,
        reasoning_runtime,
    );

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x67; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.command_history.push_back(CommandExecution {
        command: "python3 -m unittest tests.test_path_utils -v".to_string(),
        stdout: String::new(),
        stderr: "FAIL".to_string(),
        exit_code: 1,
        timestamp_ms: 1,
        step_index: 0,
    });
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
        )
        .expect("insert worker state");
    persist_worker_assignment(&mut state, session_id, &patch_assignment())
        .expect("persist worker assignment");

    let repair = attempt_refusal_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        "Empty content (reason: stop)",
    )
    .await
    .expect("refusal repair should complete");

    assert!(repair.repaired_tool.is_none());
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "refusal_repair_skipped=no_deterministic_followup"));
}

#[tokio::test(flavor = "multi_thread")]
async fn refusal_repair_uses_goal_snapshot_write_after_command_failure() {
    let fast_runtime = Arc::new(RepairRecordingRuntime::default());
    let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
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

    let repair = attempt_refusal_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        "Empty content (reason: stop)",
    )
    .await
    .expect("refusal repair should complete");

    match repair.repaired_tool.expect("expected repaired tool") {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            assert_eq!(path, "path_utils.py");
            assert_eq!(line_number, None);
            assert!(content.contains("while \"//\" in normalized"));
            assert!(content.contains("prefix = \"./\""));
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "refusal_repair_succeeded=true"));
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "refusal_repair_runtime=deterministic"));
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
async fn refusal_repair_recovers_edit_tool_after_command_failure() {
    let fast_runtime = Arc::new(RepairRecordingRuntime::default());
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
    let session_id = [0x68; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    worker_state.recent_actions = vec![
        "attempt::NoEffectAfterAction::first".to_string(),
        "attempt::UnexpectedState::second".to_string(),
    ];
    record_targeted_check_failure(&mut worker_state);
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
        )
        .expect("insert worker state");
    persist_worker_assignment(&mut state, session_id, &patch_assignment())
        .expect("persist worker assignment");

    let repair = attempt_refusal_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        "Empty content (reason: stop)",
    )
    .await
    .expect("refusal repair should complete");

    match repair.repaired_tool.expect("expected repaired tool") {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            assert_eq!(path, "path_utils.py");
            assert_eq!(line_number, None);
            assert!(content.contains("while \"//\" in normalized"));
            assert!(content.contains("prefix = \"./\""));
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "refusal_repair_succeeded=true"));
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "refusal_repair_runtime=reasoning"));
    assert!(repair.verification_checks.iter().any(|check| {
        check == "refusal_repair_patch_tool_suppressed_after_command_failure=true"
    }));
    let fast_seen_tools = fast_runtime
        .seen_tools
        .lock()
        .expect("seen_tools mutex poisoned");
    assert_eq!(fast_seen_tools.len(), 1);
    assert!(!fast_seen_tools[0]
        .iter()
        .any(|tool_name| tool_name == "filesystem__patch"));
    let seen_tools = reasoning_runtime
        .seen_tools
        .lock()
        .expect("seen_tools mutex poisoned");
    assert_eq!(seen_tools.len(), 1);
    assert!(!seen_tools[0]
        .iter()
        .any(|tool_name| tool_name == "sys__exec_session"));
    assert!(!seen_tools[0]
        .iter()
        .any(|tool_name| tool_name == "filesystem__patch"));
}

#[tokio::test(flavor = "multi_thread")]
async fn invalid_tool_repair_falls_back_to_reasoning_after_fast_error() {
    let fast_runtime = Arc::new(RepairRecordingRuntime::default());
    fast_runtime
        .outputs
        .lock()
        .expect("outputs mutex poisoned")
        .push(Err(VmError::HostError(
            "LLM_REFUSAL: Empty content (reason: stop)".to_string(),
        )));
    let reasoning_runtime = Arc::new(RepairRecordingRuntime::default());
    reasoning_runtime
        .outputs
        .lock()
        .expect("outputs mutex poisoned")
        .push(Ok(
            br#"{"name":"filesystem__patch","arguments":{"path":"path_utils.py","search":"def normalize_fixture_path(raw_path: str) -> str:\n    return raw_path","replace":"def normalize_fixture_path(raw_path: str) -> str:\n    return raw_path.strip().replace(\"\\\\\", \"/\")"}}"#
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

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x44; 32];
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
            .expect("expected repaired tool")
            .name_string(),
        "filesystem__patch"
    );
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "invalid_tool_call_repair_runtime_fallback=true"));
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "invalid_tool_call_repair_runtime=reasoning"));
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
        1
    );
}
