use super::*;

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_synthesizes_code_block_write_before_runtime() {
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
    let session_id = [0x66; 32];
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
            "Based on the previous steps, we need to update the `normalize_fixture_path` ",
            "function in `path_utils.py`.\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n",
            "```\n\n",
            "Here is the updated function:\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"/\").lstrip(\"./\")\n",
            "```\n\n",
            "Now, let's apply this change using `filesystem__patch`.\n"
        ),
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    let repaired_tool = repair.repaired_tool.clone().unwrap_or_else(|| {
        panic!(
            "expected repaired tool; checks={:?}",
            repair.verification_checks
        )
    });

    match repaired_tool {
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
        check == "invalid_tool_call_repair_deterministic_recovery=code_block_write"
    }));
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_source=fenced_code_blocks"
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
async fn patch_build_verify_invalid_tool_repair_aligns_code_block_indentation_before_runtime() {
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
            "Based on the previous output, the current implementation is:\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            " return raw_path.strip().replace(\"\\\\\", \"/\")\n",
            "```\n\n",
            "The updated function should look like this:\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            " return raw_path.replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"/\").lstrip(\"./\")\n",
            "```\n"
        ),
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    let repaired_tool = repair.repaired_tool.clone().unwrap_or_else(|| {
        panic!(
            "expected repaired tool; checks={:?}",
            repair.verification_checks
        )
    });

    match repaired_tool {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            assert_eq!(path, "path_utils.py");
            assert_eq!(line_number, None);
            assert!(content.contains("\n    \"\"\"Normalize a repo-relative path"));
            assert!(content.contains("replace(\"//\", \"/\")"));
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_alignment=python_function_indent"
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
async fn patch_build_verify_invalid_tool_repair_synthesizes_retained_multiblock_write_before_runtime(
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
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    let repaired_tool = repair.repaired_tool.clone().unwrap_or_else(|| {
        panic!(
            "expected repaired tool; checks={:?}",
            repair.verification_checks
        )
    });

    match repaired_tool {
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

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_ignores_trailing_example_lines_in_fenced_block_before_runtime(
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

    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    let original = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
    );
    fs::write(&path_utils, original).expect("write fixture source");

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x6c; 32];
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
    persist_worker_assignment(&mut state, session_id, &patch_assignment())
        .expect("persist worker assignment");

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        concat!(
            "portun normalize_fixture_path to convert backslashes to forward slashes, collapse duplicate separators, and preserve a leading ./ or /. The current implementation is:\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            " return raw_path.strip().replace(\"\\\\\", \"/\")\n",
            "```\n\n",
            "The updated function should look like this:\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            " \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            " raw_path = raw_path.strip().replace(\"\\\\\", \"/\")\n",
            " while \"//\" in raw_path:\n",
            "  raw_path = raw_path.replace(\"//\", \"/\")\n",
            " return raw_path\n",
            "\n",
            "# Example usage and verification\n",
            "print(normalize_fixture_path(\"./foo//bar\"))\n",
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
            assert!(content.contains("while \"//\" in raw_path:"));
            assert!(content.contains("return raw_path"));
            assert!(!content.contains("print(normalize_fixture_path"));
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
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
async fn patch_build_verify_invalid_tool_repair_synthesizes_goal_constrained_snapshot_write_before_runtime(
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

    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    fs::write(
        &path_utils,
        concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\").lstrip(\"/\")\n"
        ),
    )
    .expect("write fixture source");

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x7d; 32];
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
            "The focused verification command still shows one failing path-normalization case. ",
            "I will update `path_utils.py` to fully preserve the leading prefix while collapsing duplicate separators before rerunning tests."
        ),
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    let repaired_tool = repair.repaired_tool.clone().unwrap_or_else(|| {
        panic!(
            "expected repaired tool; checks={:?}",
            repair.verification_checks
        )
    });

    match repaired_tool {
        AgentTool::FsWrite {
            path,
            content,
            line_number,
        } => {
            assert_eq!(path, "path_utils.py");
            assert_eq!(line_number, None);
            assert!(content.contains("prefix = \"\""), "content was: {content}");
            assert!(
                content.contains("while \"//\" in normalized"),
                "content was: {content}"
            );
            assert!(
                content.contains("return prefix + normalized"),
                "content was: {content}"
            );
            assert!(
                !content.contains(".lstrip(\"./\")"),
                "content was: {content}"
            );
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
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
async fn patch_build_verify_invalid_tool_repair_prefers_goal_snapshot_over_inline_code_segments_for_path_parity(
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

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x7e; 32];
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
            "Given that the initial verification command failed, we need to update the ",
            "`normalize_fixture_path` function in `path_utils.py` to ensure it correctly ",
            "handles backslashes and collapses duplicate separators.\n\n",
            "Let's modify the function as follows:\n",
            "1. Replace all backslashes with forward slashes.\n",
            "2. Collapse any consecutive separators.\n",
            "3. Ensure a leading `./` or `/` is preserved.\n\n",
            "```python\n",
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    normalized = raw_path.replace(\"\\\\\", \"/\")\n",
            "    import re\n",
            "    normalized = re.sub(r'/+', '/', normalized)\n",
            "    if not (normalized.startswith('./') or normalized.startswith('/')):\n",
            "        normalized = './' + normalized\n",
            "    return normalized\n",
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
            assert!(content.contains("prefix = \"\""), "content was: {content}");
            assert!(
                content.contains("while \"//\" in normalized"),
                "content was: {content}"
            );
            assert!(
                content.contains("return prefix + normalized"),
                "content was: {content}"
            );
            assert!(
                !content.contains("normalized = './' + normalized"),
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
    assert!(!repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_source=inline_code_segments"
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
async fn patch_build_verify_deterministic_code_block_repair_rejects_goal_violating_candidate() {
    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    let original = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
    );
    fs::write(&path_utils, original).expect("write fixture source");

    let mut worker_state = build_worker_state([0x7c; 32]);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    let assignment = patch_assignment_with_path_parity_goal();
    let allowed_tool_names = assignment
        .allowed_tools
        .iter()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    let raw_tool_output = concat!(
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
        "    return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").lstrip(\"./\")\n",
        "```\n"
    );
    let mut verification_checks = Vec::new();
    let repaired_tool = super::synthesize_patch_build_verify_code_block_edit_repair(
        &worker_state,
        Some(&assignment),
        &allowed_tool_names,
        raw_tool_output,
        &mut verification_checks,
    )
    .expect("deterministic repair should be synthesized");

    let validated = super::validate_patch_build_verify_deterministic_edit_repair(
        &worker_state,
        Some(&assignment),
        raw_tool_output,
        repaired_tool,
        &mut verification_checks,
        "code_block",
    )
    .await
    .expect("validation should succeed");

    assert!(matches!(
        validated,
        super::DeterministicEditRepairValidation::Rejected(_)
    ));
    assert!(verification_checks.iter().any(|check| {
        check
            == "invalid_tool_call_repair_runtime_deterministic_code_block_goal_path_prefix_violation=true"
    }));
    assert!(verification_checks.iter().any(|check| {
        check
            == "invalid_tool_call_repair_deterministic_code_block_rejected=deterministic_code_block:goal_path_prefix_violation"
    }));
}

#[tokio::test(flavor = "multi_thread")]
async fn patch_build_verify_invalid_tool_repair_synthesizes_inline_code_write_before_runtime() {
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
    let session_id = [0x68; 32];
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
    persist_worker_assignment(&mut state, session_id, &patch_assignment())
        .expect("persist worker assignment");

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        concat!(
            "normalize_fixture_path(raw_path: str) -> str:\n",
            "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "normalized = raw_path.replace(\"\\\\\", \"/\").strip()\n",
            "return normalized\n\n",
            "# Verify the change\n",
            "sys__exec_session({\"command\": \"python3 -m unittest tests.test_path_utils -v\"})\n"
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
            assert!(content.contains("normalized = raw_path.replace(\"\\\\\", \"/\").strip()"));
            assert!(content.contains("return normalized"));
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_recovery=inline_code_write"
    }));
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_source=inline_code_segments"
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
async fn patch_build_verify_invalid_tool_repair_recovers_exact_single_line_inline_edit_from_retained_trace(
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

    let repo = tempdir().expect("tempdir should succeed");
    let path_utils = repo.path().join("path_utils.py");
    let original = concat!(
        "def normalize_fixture_path(raw_path: str) -> str:\n",
        "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
        "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
    );
    fs::write(&path_utils, original).expect("write fixture source");

    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let session_id = [0x72; 32];
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
    persist_worker_assignment(&mut state, session_id, &patch_assignment())
        .expect("persist worker assignment");

    let repair = attempt_invalid_tool_call_repair(
        &service,
        &mut state,
        &worker_state,
        session_id,
        concat!(
            "portun normalize_fixture_path(raw_path: str) -> str: ",
            "\"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\" ",
            "return raw_path.strip().replace(\"\\\\\", \"/\").replace(\"//\", \"/\").strip(\"/\")\n"
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
            assert!(content.contains("strip(\"/\")"));
        }
        other => panic!("expected filesystem__write_file, got {:?}", other),
    }
    assert!(repair.verification_checks.iter().any(|check| {
        check == "invalid_tool_call_repair_deterministic_recovery=inline_code_write"
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
async fn patch_build_verify_invalid_tool_repair_synthesizes_refresh_read_after_patch_miss_prose() {
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
    let session_id = [0x73; 32];
    let key = get_state_key(&session_id);
    let mut worker_state = build_worker_state(session_id);
    worker_state.working_directory = repo.path().to_string_lossy().to_string();
    record_targeted_check_failure(&mut worker_state);
    mark_execution_receipt_with_value(
        &mut worker_state.tool_execution_log,
        "workspace_patch_miss_observed",
        "step=7;tool=filesystem__patch;path=path_utils.py;reason=search_block_not_found"
            .to_string(),
    );
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
        concat!(
            "Fortunately, I will proceed by reading the `path_utils.py` file to identify the correct block of code to patch.\n\n",
            "First, let's read the content of `path_utils.py`.\n"
        ),
        "JSON Syntax Error: expected value at line 1 column 1",
    )
    .await
    .expect("repair attempt should succeed");

    match repair.repaired_tool.expect("expected repaired tool") {
        AgentTool::FsRead { path } => assert_eq!(path, "path_utils.py"),
        other => panic!("expected filesystem__read_file, got {:?}", other),
    }
    assert!(repair
        .verification_checks
        .iter()
        .any(|check| { check == "invalid_tool_call_repair_deterministic_recovery=refresh_read" }));
    assert_eq!(
        runtime
            .seen_inputs
            .lock()
            .expect("seen_inputs mutex poisoned")
            .len(),
        0
    );
}
