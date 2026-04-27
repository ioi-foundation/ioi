use super::*;

#[tokio::test(flavor = "current_thread")]
async fn await_child_worker_result_steps_running_child_once() {
    let (tx, _rx) = tokio::sync::broadcast::channel(16);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state_with_goal("Summarize the delegated worker", 64);

    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x31; 32],
        "Inspect the repo and return a bounded context brief.",
        32,
        None,
        Some("context_worker"),
        Some("repo_context_brief"),
        None,
        None,
        None,
        None,
        2,
        0,
    )
    .await
    .expect("delegated child should spawn");

    let child_key = get_state_key(&spawned.child_session_id);
    let child_bytes = state
        .get(&child_key)
        .expect("child lookup should succeed")
        .expect("child state should exist");
    let mut child_state: AgentState =
        codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
    let initial_step_count = child_state.step_count;
    child_state.execution_queue.push(ActionRequest {
            target: ActionTarget::Custom("agent__complete".to_string()),
            params: serde_jcs::to_vec(&serde_json::json!({
                "result": "Likely files: path_utils.py\nTargeted checks: python3 -m unittest tests.test_path_utils -v"
            }))
            .expect("agent__complete params should encode"),
            context: ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: Some(spawned.child_session_id),
                window_id: None,
            },
            nonce: 1,
        });
    persist_agent_state(
        &mut state,
        &child_key,
        &child_state,
        service.memory_runtime.as_ref(),
    )
    .expect("child state update should persist");

    let merged = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        3,
        0,
        &hex::encode(spawned.child_session_id),
    )
    .await
    .expect("await should step the child result");

    assert!(
        merged == "Running" || merged.contains("Likely files: path_utils.py"),
        "unexpected awaited child output: {merged}"
    );
    let child_bytes = state
        .get(&child_key)
        .expect("child lookup should succeed")
        .expect("child state should exist");
    let updated_child: AgentState =
        codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
    assert!(
        updated_child.step_count > initial_step_count,
        "awaited child step should advance step count"
    );
    match merged.as_str() {
        "Running" => {
            assert!(matches!(
                updated_child.status,
                AgentStatus::Running | AgentStatus::Paused(_)
            ));
            assert!(
                load_worker_session_result(&state, spawned.child_session_id)
                    .expect("worker result lookup should succeed")
                    .is_none(),
                "worker result should not materialize before the child completes"
            );
        }
        _ => {
            assert!(matches!(updated_child.status, AgentStatus::Completed(_)));
            let worker_result = load_worker_session_result(&state, spawned.child_session_id)
                .expect("worker result lookup should succeed")
                .expect("worker result should exist");
            assert!(worker_result.merged_at_ms.is_some());
        }
    }
}

#[tokio::test(flavor = "current_thread")]
async fn playbook_managed_child_enables_await_burst() {
    let (tx, _rx) = tokio::sync::broadcast::channel(16);
    let (service, _temp_dir) = build_test_service(tx.clone());
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state_with_goal("Summarize the delegated worker", 64);

    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x33; 32],
        "Inspect the repo and return a bounded context brief.",
        32,
        Some("unit_test_playbook"),
        Some("context_worker"),
        Some("repo_context_brief"),
        None,
        None,
        None,
        None,
        2,
        0,
    )
    .await
    .expect("delegated child should spawn");

    assert!(
        child_allows_await_burst(&state, spawned.child_session_id)
            .expect("playbook burst gating should load"),
        "playbook-managed child should be eligible for burst stepping while awaited"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn coding_patch_worker_enables_await_burst() {
    let (tx, _rx) = tokio::sync::broadcast::channel(16);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state_with_goal("Patch the workspace", 256);

    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x34; 32],
        "Implement the parity fix as a narrow patch.",
        64,
        Some("evidence_audited_patch"),
        Some("coder"),
        Some("patch_build_verify"),
        None,
        None,
        None,
        None,
        3,
        0,
    )
    .await
    .expect("coding child should spawn");

    assert!(
        child_allows_await_burst(&state, spawned.child_session_id)
            .expect("coding burst gating should load"),
        "local coding worker should stay eligible for burst stepping"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn generic_patch_build_verify_child_inherits_parent_contract_context() {
    let (tx, _rx) = tokio::sync::broadcast::channel(16);
    let (service, temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let repo = temp_dir.path().join("path-normalizer-fixture");
    std::fs::create_dir_all(repo.join("tests")).expect("fixture tests directory should exist");

    let parent_goal = format!(
            "Port the path-normalization parity fix into the repo at \"{}\". Work inside that repo root, patch only `path_utils.py`, keep `tests/test_path_utils.py` unchanged, update `normalize_fixture_path` so it converts backslashes to forward slashes, collapses duplicate separators, and preserves a leading `./` or `/`. Run the focused verification command `python3 -m unittest tests.test_path_utils -v` first, widen only if needed, verify the final postcondition, and report the touched files plus command results.",
            repo.display()
        );
    let mut parent_state = build_parent_state_with_goal(&parent_goal, 128);

    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x35; 32],
        "Edit the code in the specified file to match the regex pattern for replacing text blocks.",
        64,
        Some("evidence_audited_patch"),
        Some("coder"),
        Some("patch_build_verify"),
        None,
        None,
        None,
        None,
        3,
        0,
    )
    .await
    .expect("coding child should spawn");

    assert!(spawned
        .assignment
        .goal
        .contains("[PARENT PLAYBOOK CONTEXT]"));
    assert!(spawned
        .assignment
        .goal
        .contains("delegated_task_contract: Port the path-normalization parity fix"));
    assert!(spawned
        .assignment
        .goal
        .contains("- likely_files: path_utils.py; tests/test_path_utils.py"));
    assert!(spawned
        .assignment
        .goal
        .contains("- targeted_checks: python3 -m unittest tests.test_path_utils -v"));
    assert!(spawned
        .assignment
        .goal
        .contains("converts backslashes to forward slashes"));
    assert!(spawned
        .assignment
        .goal
        .contains("preserves a leading `./` or `/`"));
}

#[tokio::test(flavor = "current_thread")]
async fn citation_audit_worker_enables_await_burst() {
    let (tx, _rx) = tokio::sync::broadcast::channel(16);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state_with_goal("Verify the cited brief before merge", 128);

    let spawned = spawn_delegated_child_session(
            &service,
            &mut state,
            &mut parent_state,
            [0x36; 32],
            "Verify whether the cited brief for the latest NIST post-quantum cryptography standards is current, grounded, and supported by independent sources.",
            64,
            Some("citation_grounded_brief"),
            Some("verifier"),
            Some("citation_audit"),
            None,
            None,
            None,
            None,
            4,
            0,
        )
        .await
        .expect("citation verifier should spawn");

    assert!(
        child_allows_await_burst(&state, spawned.child_session_id)
            .expect("citation verifier burst gating should load"),
        "receipt-bound citation verifier should stay eligible for burst stepping"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn postcondition_audit_worker_enables_await_burst() {
    let (tx, _rx) = tokio::sync::broadcast::channel(16);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state_with_goal("Verify the claimed postcondition", 128);

    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x37; 32],
        "Verify whether the parser regression fix satisfies the postcondition.",
        64,
        Some("unit_test_playbook"),
        Some("verifier"),
        Some("postcondition_audit"),
        None,
        None,
        None,
        None,
        4,
        0,
    )
    .await
    .expect("postcondition verifier should spawn");

    assert!(
        child_allows_await_burst(&state, spawned.child_session_id)
            .expect("postcondition verifier burst gating should load"),
        "local postcondition verifier should stay eligible for burst stepping"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn research_worker_uses_bounded_await_burst_for_web_workflow() {
    let (tx, _rx) = tokio::sync::broadcast::channel(16);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state_with_goal("Research the current standards", 128);

    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x35; 32],
        "Research the latest standards and return a cited brief.",
        64,
        Some("citation_grounded_brief"),
        Some("researcher"),
        Some("live_research_brief"),
        None,
        None,
        None,
        None,
        4,
        0,
    )
    .await
    .expect("research child should spawn");

    assert!(
        child_allows_await_burst(&state, spawned.child_session_id)
            .expect("research burst gating should load"),
        "web-facing research worker should stay eligible for a bounded await burst"
    );
    let child_state = load_child_state(
        &state,
        service.memory_runtime.as_ref(),
        spawned.child_session_id,
        &hex::encode(spawned.child_session_id),
    )
    .expect("research child state should load");
    assert_eq!(
        await_child_burst_step_limit(&state, spawned.child_session_id, &child_state)
            .expect("research burst limit should load"),
        LIVE_RESEARCH_AWAIT_BURST_STEPS
    );
}

#[tokio::test(flavor = "current_thread")]
async fn await_child_worker_result_resumes_retry_blocked_child_once() {
    let (tx, _rx) = tokio::sync::broadcast::channel(16);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state_with_goal("Summarize the delegated worker", 64);

    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x32; 32],
        "Inspect repo context and return a bounded context brief.",
        32,
        None,
        Some("context_worker"),
        Some("repo_context_brief"),
        None,
        None,
        None,
        None,
        2,
        0,
    )
    .await
    .expect("delegated child should spawn");

    let child_key = get_state_key(&spawned.child_session_id);
    let child_bytes = state
        .get(&child_key)
        .expect("child lookup should succeed")
        .expect("child state should exist");
    let mut child_state: AgentState =
        codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
    child_state.status =
        AgentStatus::Paused("Retry blocked: unchanged AttemptKey for UnexpectedState".into());
    child_state.execution_queue.push(ActionRequest {
            target: ActionTarget::Custom("agent__complete".to_string()),
            params: serde_jcs::to_vec(&serde_json::json!({
                "result": "Likely files: path_utils.py\nTargeted checks: python3 -m unittest tests.test_path_utils -v"
            }))
            .expect("agent__complete params should encode"),
            context: ActionContext {
                agent_id: "desktop_agent".to_string(),
                session_id: Some(spawned.child_session_id),
                window_id: None,
            },
            nonce: 1,
        });
    persist_agent_state(
        &mut state,
        &child_key,
        &child_state,
        service.memory_runtime.as_ref(),
    )
    .expect("child state update should persist");

    let merged = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        3,
        0,
        &hex::encode(spawned.child_session_id),
    )
    .await
    .expect("await should resume and step the child result");

    assert!(
        merged.starts_with("Running") || merged.contains("Likely files: path_utils.py"),
        "unexpected awaited child output after retry-block resume: {merged}"
    );
    let child_bytes = state
        .get(&child_key)
        .expect("child lookup should succeed")
        .expect("child state should exist");
    let updated_child: AgentState =
        codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
    assert!(
        !matches!(
            &updated_child.status,
            AgentStatus::Paused(reason) if retry_blocked_pause_reason(reason)
        ),
        "retry-blocked child should leave the retry-block pause after awaited resume"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn await_child_worker_result_merges_observed_patch_completion_from_retry_blocked_pause() {
    let (tx, _rx) = tokio::sync::broadcast::channel(16);
    let (service, temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state_with_goal("Patch the workspace", 256);

    let repo = temp_dir.path().join("path-normalizer-fixture");
    std::fs::create_dir_all(repo.join("tests")).expect("fixture tests directory should exist");
    std::fs::write(
        repo.join("path_utils.py"),
        concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        ),
    )
    .expect("fixture source should exist");
    std::fs::write(repo.join("tests/test_path_utils.py"), "import unittest\n")
        .expect("fixture test should exist");

    let goal = format!(
            "Port the path-normalization parity fix into the repo at \"{}\". Work inside that repo root, patch only `path_utils.py`, keep `tests/test_path_utils.py` unchanged, and return touched files plus command results.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v",
            repo.display()
        );
    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x73; 32],
        &goal,
        96,
        Some("evidence_audited_patch"),
        Some("coder"),
        Some("patch_build_verify"),
        None,
        None,
        None,
        None,
        2,
        0,
    )
    .await
    .expect("patch child should spawn");

    let child_key = get_state_key(&spawned.child_session_id);
    let child_bytes = state
        .get(&child_key)
        .expect("child lookup should succeed")
        .expect("child state should exist");
    let mut child_state: AgentState =
        codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
    child_state.status =
        AgentStatus::Paused("Retry blocked: unchanged AttemptKey for UnexpectedState".into());
    child_state.command_history.push_back(CommandExecution {
        command: "python3 -m unittest tests.test_path_utils -v".to_string(),
        exit_code: 1,
        stdout: String::new(),
        stderr: "FAILED (failures=2)".to_string(),
        timestamp_ms: 1,
        step_index: 2,
    });
    child_state.command_history.push_back(CommandExecution {
        command: "python3 -m unittest tests.test_path_utils -v".to_string(),
        exit_code: 0,
        stdout: "OK".to_string(),
        stderr: String::new(),
        timestamp_ms: 2,
        step_index: 5,
    });
    child_state.tool_execution_log.insert(
        "evidence::workspace_edit_applied=true".to_string(),
        crate::agentic::runtime::types::ToolCallStatus::Executed(format!(
            "step=4;tool=file__write;path={}",
            repo.join("path_utils.py").display()
        )),
    );
    persist_agent_state(
        &mut state,
        &child_key,
        &child_state,
        service.memory_runtime.as_ref(),
    )
    .expect("child state update should persist");

    let merged = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        3,
        0,
        &hex::encode(spawned.child_session_id),
    )
    .await
    .expect("await should merge observed completion from retry-blocked pause");

    assert!(merged.contains("Touched files: path_utils.py"), "{merged}");
    assert!(
        merged.contains("advanced to 'Verify targeted tests'"),
        "{merged}"
    );

    let child_bytes = state
        .get(&child_key)
        .expect("child lookup should succeed")
        .expect("child state should exist");
    let updated_child: AgentState =
        codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
    assert!(matches!(updated_child.status, AgentStatus::Completed(_)));
}

#[tokio::test(flavor = "current_thread")]
async fn await_child_worker_result_extends_burst_for_patch_verify_post_edit_followup() {
    let (tx, _rx) = tokio::sync::broadcast::channel(16);
    let (service, temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state_with_goal("Patch the workspace", 128);
    let parent_key = get_state_key(&parent_state.session_id);
    state
        .insert(
            &parent_key,
            &codec::to_bytes_canonical(&parent_state).expect("parent state encode"),
        )
        .expect("parent state insert should succeed");
    let parent_rules = ActionRules {
        policy_id: "capabilities-suite".to_string(),
        defaults: DefaultPolicy::AllowAll,
        ..ActionRules::default()
    };
    let parent_policy_key = [AGENT_POLICY_PREFIX, parent_state.session_id.as_slice()].concat();
    state
        .insert(
            &parent_policy_key,
            &codec::to_bytes_canonical(&parent_rules).expect("parent policy encode"),
        )
        .expect("parent policy insert should succeed");

    let repo = temp_dir.path().join("path-normalizer-fixture");
    std::fs::create_dir_all(repo.join("tests")).expect("fixture tests directory should exist");
    std::fs::write(
        repo.join("path_utils.py"),
        concat!(
            "def normalize_fixture_path(raw_path: str) -> str:\n",
            "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
            "    return raw_path.strip().replace(\"\\\\\", \"/\")\n"
        ),
    )
    .expect("fixture source should exist");
    std::fs::write(repo.join("tests/test_path_utils.py"), "import unittest\n")
        .expect("fixture test should exist");

    let goal = format!(
            "Port the path-normalization parity fix into the repo at \"{}\". Work inside that repo root, patch only `path_utils.py`, keep `tests/test_path_utils.py` unchanged, and return touched files plus command results.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v",
            repo.display()
        );
    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x72; 32],
        &goal,
        96,
        Some("evidence_audited_patch"),
        Some("coder"),
        Some("patch_build_verify"),
        None,
        None,
        None,
        None,
        2,
        0,
    )
    .await
    .expect("patch child should spawn");

    let child_key = get_state_key(&spawned.child_session_id);
    let child_bytes = state
        .get(&child_key)
        .expect("child lookup should succeed")
        .expect("child state should exist");
    let mut child_state: AgentState =
        codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
    child_state
        .command_history
        .push_back(crate::agentic::runtime::types::CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 1,
            stdout: "targeted tests failed".to_string(),
            stderr: String::new(),
            timestamp_ms: 1,
            step_index: 0,
        });

    let repo_path = repo.to_string_lossy().to_string();
    let tests_path = repo.join("tests").to_string_lossy().to_string();
    let source_path = repo.join("path_utils.py").to_string_lossy().to_string();
    let test_path = repo
        .join("tests/test_path_utils.py")
        .to_string_lossy()
        .to_string();
    let context = ActionContext {
        agent_id: "desktop_agent".to_string(),
        session_id: Some(spawned.child_session_id),
        window_id: None,
    };

    child_state.execution_queue.push(ActionRequest {
        target: ActionTarget::FsRead,
        params: serde_jcs::to_vec(&serde_json::json!({
            "__ioi_tool_name": "file__list",
            "path": repo_path
        }))
        .expect("list repo params should encode"),
        context: context.clone(),
        nonce: 1,
    });
    child_state.execution_queue.push(ActionRequest {
        target: ActionTarget::FsRead,
        params: serde_jcs::to_vec(&serde_json::json!({
            "__ioi_tool_name": "file__list",
            "path": tests_path
        }))
        .expect("list tests params should encode"),
        context: context.clone(),
        nonce: 2,
    });
    child_state.execution_queue.push(ActionRequest {
        target: ActionTarget::FsRead,
        params: serde_jcs::to_vec(&serde_json::json!({ "path": source_path }))
            .expect("read source params should encode"),
        context: context.clone(),
        nonce: 3,
    });
    child_state.execution_queue.push(ActionRequest {
        target: ActionTarget::FsRead,
        params: serde_jcs::to_vec(&serde_json::json!({ "path": test_path }))
            .expect("read test params should encode"),
        context: context.clone(),
        nonce: 4,
    });
    child_state.execution_queue.push(ActionRequest {
        target: ActionTarget::FsRead,
        params: serde_jcs::to_vec(&serde_json::json!({
            "path": repo.to_string_lossy().to_string(),
            "regex": "normalize_fixture_path"
        }))
        .expect("search params should encode"),
        context: context.clone(),
        nonce: 5,
    });
    child_state.execution_queue.push(ActionRequest {
        target: ActionTarget::FsWrite,
        params: serde_jcs::to_vec(&serde_json::json!({
            "path": "path_utils.py",
            "content": concat!(
                "def normalize_fixture_path(raw_path: str) -> str:\n",
                "    \"\"\"Normalize a repo-relative path coming from mixed slash inputs.\"\"\"\n",
                "    prefix = \"\"\n",
                "    if raw_path.startswith(\"./\"):\n",
                "        prefix = \"./\"\n",
                "        raw_path = raw_path[2:]\n",
                "    elif raw_path.startswith(\"/\"):\n",
                "        prefix = \"/\"\n",
                "        raw_path = raw_path[1:]\n",
                "    normalized = raw_path.replace(\"\\\\\", \"/\")\n",
                "    while \"//\" in normalized:\n",
                "        normalized = normalized.replace(\"//\", \"/\")\n",
                "    return prefix + normalized\n"
            )
        }))
        .expect("write params should encode"),
        context: context.clone(),
        nonce: 6,
    });
    child_state.execution_queue.push(ActionRequest {
            target: ActionTarget::Custom("agent__complete".to_string()),
            params: serde_jcs::to_vec(&serde_json::json!({
                "result": "Touched files: path_utils.py\nVerification: python3 -m unittest tests.test_path_utils -v (queued after edit)"
            }))
            .expect("complete params should encode"),
            context,
            nonce: 7,
        });
    persist_agent_state(
        &mut state,
        &child_key,
        &child_state,
        service.memory_runtime.as_ref(),
    )
    .expect("child state update should persist");

    let merged = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        3,
        0,
        &hex::encode(spawned.child_session_id),
    )
    .await
    .expect("await should consume post-edit followup burst");

    let child_bytes = state
        .get(&child_key)
        .expect("child lookup should succeed")
        .expect("child state should exist");
    let updated_child: AgentState =
        codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
    assert!(
            merged.contains("Touched files: path_utils.py"),
            "unexpected awaited child output: {merged}; status={:?}; step_count={}; queue_len={}; next_targets={:?}; workspace_edit_receipt={:?}; recent_actions={:?}; tool_execution_log_keys={:?}; source_contents={}",
            updated_child.status,
            updated_child.step_count,
            updated_child.execution_queue.len(),
            updated_child
                .execution_queue
                .iter()
                .map(|request| format!("{:?}", request.target))
                .collect::<Vec<_>>(),
            execution_evidence_value(&updated_child.tool_execution_log, "workspace_edit_applied"),
            updated_child.recent_actions,
            updated_child
                .tool_execution_log
                .keys()
                .cloned()
                .collect::<Vec<_>>(),
            std::fs::read_to_string(repo.join("path_utils.py"))
                .unwrap_or_else(|error| format!("<read failed: {error}>")),
        );
    assert!(matches!(updated_child.status, AgentStatus::Completed(_)));
    assert!(
        execution_evidence_value(&updated_child.tool_execution_log, "workspace_edit_applied")
            .is_some(),
        "workspace edit receipt should be present after the awaited write"
    );
    let worker_result = load_worker_session_result(&state, spawned.child_session_id)
        .expect("worker result lookup should succeed")
        .expect("worker result should exist");
    assert!(worker_result
        .merged_output
        .contains("Touched files: path_utils.py"));
}
