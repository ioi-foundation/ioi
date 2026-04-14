use super::*;

#[test]
fn invalid_tool_repair_support_stays_on_coding_scopes() {
    let mut agent_state = build_worker_state([0x11; 32]);
    assert!(invalid_tool_repair_supported(
        &agent_state,
        Some(&patch_assignment())
    ));

    agent_state.resolved_intent = Some(resolved(IntentScopeProfile::CommandExecution));
    assert!(invalid_tool_repair_supported(&agent_state, None));

    agent_state.resolved_intent = Some(resolved(IntentScopeProfile::WebResearch));
    assert!(!invalid_tool_repair_supported(&agent_state, None));
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_uses_recovery_filtered_tools() {
    let runtime = Arc::new(RepairRecordingRuntime::default());
    runtime
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
        runtime.clone(),
        runtime.clone(),
    );

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x22; 32];
    let key = get_state_key(&session_id);
    let worker_state = build_worker_state(session_id);
    state
        .insert(
            &key,
            &codec::to_bytes_canonical(&worker_state).expect("encode worker state"),
        )
        .expect("insert worker state");
    let mut assignment = patch_assignment();
    assignment.goal = concat!(
        "Port the path-normalization parity fix into the repo root. Patch only `path_utils.py`, ",
        "keep `tests/test_path_utils.py` unchanged, update `normalize_fixture_path` so it ",
        "converts backslashes to forward slashes, collapses duplicate separators, and preserves ",
        "a leading `./` or `/`, then rerun `python3 -m unittest tests.test_path_utils -v` after the edit.\n\n",
        "[PARENT PLAYBOOK CONTEXT]\n",
        "- likely_files: path_utils.py; tests/test_path_utils.py\n",
        "- targeted_checks: python3 -m unittest tests.test_path_utils -v"
    )
    .to_string();
    persist_worker_assignment(&mut state, session_id, &assignment)
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
            .unwrap_or_else(|| {
                panic!(
                    "expected repaired tool; checks={:?}",
                    repair.verification_checks
                )
            })
            .name_string(),
        "filesystem__patch"
    );
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "invalid_tool_call_repair_attempted=true"));
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "invalid_tool_call_repair_runtime=fast"));
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "invalid_tool_call_repair_succeeded=true"));
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "invalid_tool_call_repair_tool=filesystem__patch"));

    let seen_tools = runtime
        .seen_tools
        .lock()
        .expect("seen_tools mutex poisoned")
        .clone();
    let repair_tools = seen_tools
        .iter()
        .find(|tool_names: &&Vec<String>| {
            tool_names
                .iter()
                .any(|name| name == "filesystem__write_file")
        })
        .expect("repair inference should record a tool set");
    assert!(repair_tools
        .iter()
        .any(|name| name == "filesystem__write_file"));
    assert!(repair_tools
        .iter()
        .any(|name| name == "filesystem__edit_line"));
    assert!(repair_tools.iter().any(|name| name == "filesystem__patch"));
    assert!(repair_tools.iter().any(|name| name == "sys__exec_session"));
    assert!(repair_tools.iter().any(|name| name == "agent__complete"));
    assert!(repair_tools.iter().any(|name| name == "system__fail"));
    assert!(!repair_tools
        .iter()
        .any(|name| name == "filesystem__read_file"));
    assert!(!repair_tools.iter().any(|name| name == "filesystem__search"));
    assert!(!repair_tools
        .iter()
        .any(|name| name == "filesystem__list_directory"));
    assert!(!repair_tools.iter().any(|name| name == "filesystem__stat"));

    let seen_inputs = runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned")
        .clone();
    let prompt = seen_inputs
        .iter()
        .map(|bytes| String::from_utf8_lossy(bytes).to_string())
        .find(|input: &String| input.contains("Malformed response to repair"))
        .expect("repair prompt should be recorded");
    assert!(prompt.contains("path_utils.py"));
    assert!(prompt.contains("filesystem__patch"));
    assert!(prompt.contains("JSON Syntax Error"));
}

#[test]
fn patch_build_verify_deterministic_allowed_tool_names_rehydrates_edit_tools_from_assignment() {
    let mut worker_state = build_worker_state([0x23; 32]);
    record_targeted_check_failure(&mut worker_state);
    let assignment = patch_assignment_with_path_parity_goal();
    let allowed_tool_names = [
        "filesystem__read_file".to_string(),
        "sys__exec_session".to_string(),
        "agent__complete".to_string(),
    ]
    .into_iter()
    .collect::<BTreeSet<_>>();
    let mut verification_checks = Vec::new();

    let hydrated = super::patch_build_verify_deterministic_allowed_tool_names(
        &worker_state,
        Some(&assignment),
        &allowed_tool_names,
        &mut verification_checks,
        "invalid_tool_call_repair",
    );

    assert!(hydrated.contains("filesystem__write_file"));
    assert!(hydrated.contains("filesystem__edit_line"));
    assert!(hydrated.contains("filesystem__read_file"));
    assert!(verification_checks.iter().any(|check| {
        check
            == "invalid_tool_call_repair_deterministic_assignment_tool_hints=filesystem__write_file|filesystem__edit_line"
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_synthesizes_targeted_exec_before_runtime() {
    let runtime = Arc::new(RepairRecordingRuntime::default());
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime.clone(),
    );

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x55; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
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
            "return raw_path.strip().replace(\"\\\\\", \"/\")\n\n",
            "Given that the function already replaces backslashes with forward slashes, ",
            "we need to ensure it also collapses duplicate separators and preserves a leading `./` or `/`.\n\n",
            "First, I will read the `path_utils.py` file to inspect its current state.\n"
        ),
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    match repair.repaired_tool.expect("expected repaired tool") {
        AgentTool::SysExecSession {
            command,
            args,
            stdin,
            ..
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
        .any(|check| { check == "invalid_tool_call_repair_deterministic_recovery=targeted_exec" }));
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| { check == "invalid_tool_call_repair_runtime=deterministic" }));
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
async fn patch_build_verify_invalid_tool_repair_synthesizes_targeted_exec_after_initial_duplicate_read_guidance(
) {
    let runtime = Arc::new(RepairRecordingRuntime::default());
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime.clone(),
    );

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x54; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = ".".to_string();
    worker_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
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
        r#"{"arguments":{"content":"tool: def normalize_fixture_path(raw_path: str) -> str:\n return raw_path.strip().replace(\"\\\\\", \"/\")","line_number":"0","path":"path_utils.py"},"name":"filesystem__edit_line"}"#,
        "Failed to parse tool call: filesystem__edit_line requires integer 'line_number' (or alias 'line')",
    )
    .await
    .expect("repair attempt should succeed");

    match repair.repaired_tool.expect("expected repaired tool") {
        AgentTool::SysExecSession {
            command,
            args,
            stdin,
            ..
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
        .any(|check| { check == "invalid_tool_call_repair_deterministic_recovery=targeted_exec" }));
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| check == "invalid_tool_call_repair_runtime=deterministic"));
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
async fn patch_build_verify_invalid_tool_repair_does_not_replay_targeted_exec_after_command_failure(
) {
    let runtime = Arc::new(RepairRecordingRuntime::default());
    runtime
        .outputs
        .lock()
        .expect("outputs mutex poisoned")
        .push(Ok(
            br#"{"name":"filesystem__patch","arguments":{"path":"path_utils.py","search":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    return raw_path.strip().replace(\"\\\\\", \"/\")","replace":"def normalize_fixture_path(raw_path: str) -> str:\n    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n    return raw_path.replace(\"\\\\\", \"/\").replace(\"//\", \"/\")"}}"#
                .to_vec(),
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
    let session_id = [0x56; 32];
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
            "normalize_fixture_path currently replaces backslashes with forward slashes, ",
            "but does not collapse duplicate separators.\n\n",
            "Let's first read `path_utils.py` and update the function.\n"
        ),
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    assert_eq!(
        repair
            .repaired_tool
            .expect("expected repaired tool")
            .name_string(),
        "filesystem__write_file"
    );
    assert!(!repair
        .verification_checks
        .iter()
        .any(|check| { check == "invalid_tool_call_repair_deterministic_recovery=targeted_exec" }));
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_source=goal_constrained_snapshot"
    }));
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_recovery=goal_constrained_snapshot_write"
    }));
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_patch_tool_suppressed_after_command_failure=true"
    }));
    assert!(runtime
        .seen_inputs
        .lock()
        .expect("seen_inputs mutex poisoned")
        .is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_replays_targeted_exec_after_workspace_edit_receipt()
{
    let runtime = Arc::new(RepairRecordingRuntime::default());
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime.clone(),
    );

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x5f; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = ".".to_string();
    worker_state.recent_actions = vec!["attempt::NoEffectAfterAction::first".to_string()];
    record_targeted_check_failure(&mut worker_state);
    worker_state.tool_execution_log.insert(
        "receipt::workspace_edit_applied=true".to_string(),
        ToolCallStatus::Executed(
            "step=2;tool=filesystem__write_file;path=path_utils.py".to_string(),
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

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        concat!(
            "We already landed the path normalization edit. ",
            "Next I should rerun the focused verification command.\n",
            "1. Re-run the targeted tests.\n",
            "2. Confirm they pass.\n"
        ),
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    match repair.repaired_tool.expect("expected repaired tool") {
        AgentTool::SysExecSession {
            command,
            args,
            stdin,
            ..
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
        .any(|check| { check == "invalid_tool_call_repair_targeted_command_rerun=post_edit" }));
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
async fn patch_build_verify_invalid_tool_repair_replays_targeted_exec_after_post_edit_unexpected_state(
) {
    let runtime = Arc::new(RepairRecordingRuntime::default());
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime.clone(),
    );

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x73; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = ".".to_string();
    worker_state.recent_actions = vec![
        "attempt::NoEffectAfterAction::first".to_string(),
        "attempt::UnexpectedState::second".to_string(),
    ];
    record_targeted_check_failure(&mut worker_state);
    worker_state.tool_execution_log.insert(
        "receipt::workspace_edit_applied=true".to_string(),
        ToolCallStatus::Executed(
            "step=4;tool=filesystem__write_file;path=path_utils.py".to_string(),
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

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        concat!(
            "The edit is already in place.\n",
            "Now rerun the focused verifier and then finish with a bounded handoff.\n"
        ),
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    match repair.repaired_tool.expect("expected repaired tool") {
        AgentTool::SysExecSession {
            command,
            args,
            stdin,
            ..
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
        .any(|check| { check == "invalid_tool_call_repair_deterministic_recovery=targeted_exec" }));
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_targeted_command_boundary=post_edit_unexpected_state"
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_prioritizes_targeted_exec_for_post_edit_code_blob()
{
    let runtime = Arc::new(RepairRecordingRuntime::default());
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime.clone(),
    );

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x8a; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = ".".to_string();
    worker_state.recent_actions = vec![
        "attempt::NoEffectAfterAction::first".to_string(),
        "attempt::UnexpectedState::second".to_string(),
    ];
    record_targeted_check_failure(&mut worker_state);
    worker_state.tool_execution_log.insert(
        "receipt::workspace_edit_applied=true".to_string(),
        ToolCallStatus::Executed(
            "step=5;tool=filesystem__write_file;path=path_utils.py".to_string(),
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

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        concat!(
            "portun normalize_fixture_path(raw_path: str) -> str: ",
            "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\" ",
            "prefix = \"\" if raw_path.startswith(\"./\"): prefix = \"./\" ",
            "raw_path = raw_path[2:] elif raw_path.startswith(\"/\"): prefix = \"/\" ",
            "raw_path = raw_path[1:] normalized = raw_path.replace(\"\\\\\", \"/\") ",
            "while \"//\" in normalized: normalized = normalized.replace(\"//\", \"/\") ",
            "return prefix + normalized\n\n",
            "The edit is already in place. First, I will read the file to ensure we have the correct context.\n"
        ),
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    match repair.repaired_tool.expect("expected repaired tool") {
        AgentTool::SysExecSession {
            command,
            args,
            stdin,
            ..
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
        .any(|check| { check == "invalid_tool_call_repair_deterministic_recovery=targeted_exec" }));
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| { check == "invalid_tool_call_repair_targeted_command_rerun=post_edit" }));
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
fn patch_build_verify_post_success_completion_rewrites_followup_patch_attempt() {
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x91; 32];
    persist_worker_assignment(
        &mut state,
        session_id,
        &patch_assignment_with_path_parity_goal(),
    )
    .expect("persist worker assignment");

    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = ".".to_string();
    worker_state.command_history.push_back(CommandExecution {
        command: "python3 -m unittest tests.test_path_utils -v".to_string(),
        exit_code: 0,
        stdout: "OK".to_string(),
        stderr: String::new(),
        timestamp_ms: 1,
        step_index: 6,
    });
    worker_state.tool_execution_log.insert(
        "receipt::workspace_edit_applied=true".to_string(),
        ToolCallStatus::Executed(
            "step=4;tool=filesystem__write_file;path=path_utils.py".to_string(),
        ),
    );

    let mut verification_checks = Vec::new();
    let rewritten = maybe_rewrite_patch_build_verify_post_success_completion(
        &state,
        &worker_state,
        session_id,
        &AgentTool::FsPatch {
            path: "path_utils.py".to_string(),
            search: "before".to_string(),
            replace: "after".to_string(),
        },
        &mut verification_checks,
    )
    .expect("expected completion rewrite");

    match rewritten {
        AgentTool::AgentComplete { result } => {
            assert!(result.contains("Touched files: path_utils.py"));
            assert!(result
                .contains("Verification: python3 -m unittest tests.test_path_utils -v (passed)"));
            assert!(result.contains("broader checks were not rerun"));
        }
        other => panic!("expected agent__complete, got {:?}", other),
    }
    assert!(verification_checks
        .iter()
        .any(|check| { check == "patch_build_verify_post_success_completion_rewritten=true" }));
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_completes_after_successful_targeted_command() {
    let runtime = Arc::new(RepairRecordingRuntime::default());
    let gui: Arc<dyn GuiDriver> = Arc::new(NoopGuiDriver);
    let service = RuntimeAgentService::new_hybrid(
        gui,
        Arc::new(TerminalDriver::new()),
        Arc::new(BrowserDriver::new()),
        runtime.clone(),
        runtime.clone(),
    );

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x92; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = ".".to_string();
    worker_state.command_history.push_back(CommandExecution {
        command: "python3 -m unittest tests.test_path_utils -v".to_string(),
        exit_code: 0,
        stdout: "OK".to_string(),
        stderr: String::new(),
        timestamp_ms: 1,
        step_index: 8,
    });
    worker_state.tool_execution_log.insert(
        "receipt::workspace_edit_applied=true".to_string(),
        ToolCallStatus::Executed(
            "step=4;tool=filesystem__write_file;path=path_utils.py".to_string(),
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

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        "I will patch path_utils.py again to be safe before wrapping up.",
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    match repair.repaired_tool.expect("expected repaired tool") {
        AgentTool::AgentComplete { result } => {
            assert!(result.contains("Touched files: path_utils.py"));
            assert!(result
                .contains("Verification: python3 -m unittest tests.test_path_utils -v (passed)"));
        }
        other => panic!("expected agent__complete, got {:?}", other),
    }
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| { check == "patch_build_verify_post_success_completion_rewritten=true" }));
    assert_eq!(
        runtime
            .seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .len(),
        0
    );
}
