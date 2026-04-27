use super::*;

#[tokio::test(flavor = "current_thread")]
async fn evidence_audited_parent_playbook_advances_across_all_steps() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(64);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic =
        "Port LocalAI lifecycle parity into the kernel-managed control plane with evidence.";
    let mut parent_state = build_parent_state_with_goal(topic, 320);

    let context = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x52; 32],
        topic,
        196,
        Some("evidence_audited_patch"),
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
    .expect("context step should spawn");
    let context_id = context.child_session_id;
    assert_eq!(
        context.assignment.workflow_id.as_deref(),
        Some("repo_context_brief")
    );

    let context_key = get_state_key(&context_id);
    let context_bytes = state
        .get(&context_key)
        .expect("context state lookup should succeed")
        .expect("context state should exist");
    let mut context_state: AgentState =
        codec::from_bytes_canonical(&context_bytes).expect("context state should decode");
    context_state.status = AgentStatus::Completed(Some(
            "Likely files: crates/services/src/model.rs; crates/services/src/router.rs\nTargeted checks: cargo test -p ioi-services routing_contracts -- --nocapture\nOpen questions: confirm verifier should stay on targeted checks unless routing evidence disagree."
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &context_key,
        &context_state,
        service.memory_runtime.as_ref(),
    )
    .expect("context state update should persist");

    let merged_context = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        3,
        0,
        &hex::encode(context_id),
    )
    .await
    .expect("context merge should advance playbook");
    assert!(merged_context.contains("Playbook: Repo Context Brief (repo_context_brief)"));
    assert!(merged_context.contains("advanced to 'Patch the workspace'"));

    let run_after_context =
        load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
            .expect("parent playbook run lookup should succeed")
            .expect("parent playbook run should exist");
    assert_eq!(run_after_context.status, ParentPlaybookStatus::Running);
    assert_eq!(
        run_after_context.steps[0].status,
        ParentPlaybookStepStatus::Completed
    );
    assert_eq!(
        run_after_context.steps[1].status,
        ParentPlaybookStepStatus::Running
    );
    let implement_id = run_after_context
        .active_child_session_id
        .expect("implement child should be active");

    let implement_key = get_state_key(&implement_id);
    let implement_bytes = state
        .get(&implement_key)
        .expect("implement state lookup should succeed")
        .expect("implement state should exist");
    let mut implement_state: AgentState =
        codec::from_bytes_canonical(&implement_bytes).expect("implement state should decode");
    assert!(implement_state.goal.contains("narrow workspace patch"));
    assert!(implement_state
        .goal
        .contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
    implement_state.status = AgentStatus::Completed(Some(
            "Touched files: crates/services/src/model.rs; crates/services/src/router.rs\nVerification: cargo check -p ioi-services (passed); cargo test -p ioi-services routing_contracts -- --nocapture (passed)\nResidual risk: broader end-to-end runtime parity still needs audit."
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &implement_key,
        &implement_state,
        service.memory_runtime.as_ref(),
    )
    .expect("implement state update should persist");

    let merged_implement = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        4,
        0,
        &hex::encode(implement_id),
    )
    .await
    .expect("implement merge should advance playbook");
    assert!(merged_implement.contains("Playbook: Patch, Build, Verify (patch_build_verify)"));
    assert!(
        merged_implement.contains("advanced to 'Verify targeted tests'"),
        "unexpected implement merge output: {}",
        merged_implement
    );

    let run_after_implement =
        load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
            .expect("parent playbook run lookup should succeed")
            .expect("parent playbook run should exist");
    assert_eq!(
        run_after_implement.steps[1].status,
        ParentPlaybookStepStatus::Completed
    );
    assert_eq!(
        run_after_implement.steps[2].status,
        ParentPlaybookStepStatus::Running,
        "unexpected playbook statuses: {:?}; active_child={:?}",
        run_after_implement
            .steps
            .iter()
            .map(|step| (
                step.label.clone(),
                step.status.clone(),
                step.child_session_id.map(hex::encode)
            ))
            .collect::<Vec<_>>(),
        run_after_implement.active_child_session_id.map(hex::encode)
    );
    let verify_id = run_after_implement
        .active_child_session_id
        .expect("verify child should be active");

    let verify_key = get_state_key(&verify_id);
    let verify_bytes = state
        .get(&verify_key)
        .expect("verify state lookup should succeed")
        .expect("verify state should exist");
    let mut verify_state: AgentState =
        codec::from_bytes_canonical(&verify_bytes).expect("verify state should decode");
    assert!(verify_state.goal.contains("targeted checks first"));
    assert!(verify_state.goal.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
    verify_state.status = AgentStatus::Completed(Some(
            "- verdict: passed\n- targeted_command_count: 2\n- targeted_pass_count: 2\n- widening_status: not_needed\n- regression_status: clear\n- notes: Focused cargo check and routing contract test passed without widening."
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &verify_key,
        &verify_state,
        service.memory_runtime.as_ref(),
    )
    .expect("verify state update should persist");

    let merged_verify = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        5,
        0,
        &hex::encode(verify_id),
    )
    .await
    .expect("verify merge should advance playbook");
    assert!(merged_verify.contains("Playbook: Targeted Test Audit (targeted_test_audit)"));
    assert!(merged_verify.contains("advanced to 'Synthesize final patch'"));
    assert!(merged_verify.contains("Patch Synthesis Handoff (patch_synthesis_handoff)"));
    assert!(merged_verify.contains("Parent playbook 'Evidence-Audited Patch' completed."));

    let run_after_verify =
        load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
            .expect("parent playbook run lookup should succeed")
            .expect("parent playbook run should exist");
    assert_eq!(
        run_after_verify.steps[2].status,
        ParentPlaybookStepStatus::Completed
    );
    assert_eq!(
        run_after_verify.steps[2]
            .coding_scorecard
            .as_ref()
            .map(|scorecard| scorecard.verdict.as_str()),
        Some("passed")
    );
    assert_eq!(
        run_after_verify.steps[2]
            .coding_scorecard
            .as_ref()
            .map(|scorecard| scorecard.targeted_pass_count),
        Some(2)
    );
    assert_eq!(
        run_after_verify.steps[3].status,
        ParentPlaybookStepStatus::Completed
    );
    assert!(run_after_verify.active_child_session_id.is_none());

    let final_run =
        load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
            .expect("final parent playbook run lookup should succeed")
            .expect("final parent playbook run should exist");
    assert_eq!(final_run.status, ParentPlaybookStatus::Completed);
    let parent_completion = match &parent_state.status {
        AgentStatus::Completed(Some(output)) => output,
        other => panic!("expected completed parent status, got {:?}", other),
    };
    assert!(parent_completion.contains("status: ready"));
    assert!(final_run.completed_at_ms.is_some());
    assert_eq!(parent_state.child_session_ids.len(), 4);
    assert!(final_run
        .steps
        .iter()
        .all(|step| step.status == ParentPlaybookStepStatus::Completed));
    assert_eq!(
        final_run.steps[3]
            .patch_synthesis
            .as_ref()
            .map(|summary| summary.status.as_str()),
        Some("ready")
    );

    let mut parent_receipts = Vec::new();
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            if let WorkloadReceipt::ParentPlaybook(receipt) = receipt_event.receipt {
                parent_receipts.push(receipt);
            }
        }
    }

    let parent_receipt_phases = parent_receipts
        .iter()
        .map(|receipt| receipt.phase.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        parent_receipt_phases,
        vec![
            "started".to_string(),
            "step_spawned".to_string(),
            "step_completed".to_string(),
            "step_spawned".to_string(),
            "step_completed".to_string(),
            "step_spawned".to_string(),
            "step_completed".to_string(),
            "step_spawned".to_string(),
            "step_completed".to_string(),
            "completed".to_string(),
        ]
    );
    assert!(parent_receipts
        .iter()
        .all(|receipt| receipt.route_family == "coding"));
    assert!(parent_receipts
        .iter()
        .all(|receipt| receipt.topology == "planner_specialist_verifier"));
    assert!(parent_receipts
        .iter()
        .all(|receipt| receipt.planner_authority == "kernel"));
    assert!(parent_receipts
        .iter()
        .all(|receipt| receipt.verifier_role == "test_verifier"));
    assert_eq!(
        parent_receipts
            .first()
            .map(|receipt| receipt.verifier_state.as_str()),
        Some("queued")
    );
    assert_eq!(
        parent_receipts
            .iter()
            .find(|receipt| {
                receipt.phase == "step_spawned" && receipt.step_id.as_deref() == Some("verify")
            })
            .map(|receipt| receipt.verifier_state.as_str()),
        Some("active")
    );
    assert_eq!(
        parent_receipts
            .iter()
            .find(|receipt| {
                receipt.phase == "step_completed" && receipt.step_id.as_deref() == Some("verify")
            })
            .and_then(|receipt| receipt.coding_scorecard.as_ref())
            .map(|scorecard| scorecard.verdict.as_str()),
        Some("passed")
    );
    assert_eq!(
        parent_receipts
            .last()
            .and_then(|receipt| receipt.patch_synthesis.as_ref())
            .map(|summary| summary.status.as_str()),
        Some("ready")
    );
    assert_eq!(
        parent_receipts
            .last()
            .map(|receipt| receipt.verifier_state.as_str()),
        Some("passed")
    );
    assert_eq!(
        parent_receipts
            .last()
            .map(|receipt| receipt.verifier_outcome.as_str()),
        Some("pass")
    );
}

#[tokio::test(flavor = "current_thread")]
async fn evidence_audited_patch_summary_only_implement_handoff_bootstraps_verifier_child() {
    let (tx, _rx) = tokio::sync::broadcast::channel(16);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic = "Port the path-normalization parity fix into the kernel-managed control plane.";
    let mut parent_state = build_parent_state_with_goal(topic, 240);

    let context = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x52; 32],
        topic,
        128,
        Some("evidence_audited_patch"),
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
    .expect("context step should spawn");
    let context_key = get_state_key(&context.child_session_id);
    let context_bytes = state
        .get(&context_key)
        .expect("context state lookup should succeed")
        .expect("context state should exist");
    let mut context_state: AgentState =
        codec::from_bytes_canonical(&context_bytes).expect("context state should decode");
    context_state.status = AgentStatus::Completed(Some(
            "Likely files: path_utils.py; tests/test_path_utils.py\nTargeted checks: python3 -m unittest tests.test_path_utils -v"
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &context_key,
        &context_state,
        service.memory_runtime.as_ref(),
    )
    .expect("context state update should persist");

    let merged_context = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        3,
        0,
        &hex::encode(context.child_session_id),
    )
    .await
    .expect("context merge should advance playbook");
    assert!(merged_context.contains("advanced to 'Patch the workspace'"));

    let run_after_context =
        load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
            .expect("playbook run lookup should succeed")
            .expect("playbook run should exist");
    let implement_id = run_after_context
        .active_child_session_id
        .expect("implement child should be active");
    let implement_key = get_state_key(&implement_id);
    let implement_bytes = state
        .get(&implement_key)
        .expect("implement state lookup should succeed")
        .expect("implement state should exist");
    let mut implement_state: AgentState =
        codec::from_bytes_canonical(&implement_bytes).expect("implement state should decode");
    implement_state.status = AgentStatus::Completed(Some(
            "Successfully implemented and verified the path-normalization parity fix in 'path_utils.py'. The focused verification command passed all tests without issues.".to_string(),
        ));
    implement_state
        .command_history
        .push_back(crate::agentic::runtime::types::CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 0,
            stdout: String::new(),
            stderr: "OK".to_string(),
            timestamp_ms: 1,
            step_index: 8,
        });
    implement_state.tool_execution_log.insert(
        "evidence::workspace_edit_applied=true".to_string(),
        crate::agentic::runtime::types::ToolCallStatus::Executed(
            "step=7;tool=file__write;path=path_utils.py".to_string(),
        ),
    );
    persist_agent_state(
        &mut state,
        &implement_key,
        &implement_state,
        service.memory_runtime.as_ref(),
    )
    .expect("implement state update should persist");

    let merged_implement = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        4,
        0,
        &hex::encode(implement_id),
    )
    .await
    .expect("implement merge should advance playbook");
    assert!(
        merged_implement.contains("advanced to 'Verify targeted tests'"),
        "unexpected implement merge output: {}",
        merged_implement
    );

    let run_after_implement =
        load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
            .expect("playbook run lookup should succeed")
            .expect("playbook run should exist");
    assert_eq!(run_after_implement.status, ParentPlaybookStatus::Completed);
    assert_eq!(
        run_after_implement.steps[1].status,
        ParentPlaybookStepStatus::Completed
    );
    assert_eq!(
        run_after_implement.steps[2].status,
        ParentPlaybookStepStatus::Completed
    );
    assert_eq!(
        run_after_implement.steps[3].status,
        ParentPlaybookStepStatus::Completed
    );
    assert!(run_after_implement.active_child_session_id.is_none());
    assert!(
        merged_implement.contains("Playbook: Targeted Test Audit (targeted_test_audit)"),
        "{merged_implement}"
    );
    assert!(
        merged_implement.contains("Playbook: Patch Synthesis Handoff (patch_synthesis_handoff)"),
        "{merged_implement}"
    );
    assert!(
        merged_implement.contains("Parent playbook 'Evidence-Audited Patch' completed."),
        "{merged_implement}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn evidence_audited_parent_playbook_replay_resets_downstream_blocked_steps() {
    let (tx, _rx) = tokio::sync::broadcast::channel(64);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic = "Patch only the targeted repo file and verify the focused test first.";
    let mut parent_state = build_parent_state_with_goal(topic, 320);

    let context = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x61; 32],
        topic,
        96,
        Some("evidence_audited_patch"),
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
    .expect("context step should spawn");
    let context_key = get_state_key(&context.child_session_id);
    let context_bytes = state
        .get(&context_key)
        .expect("context state lookup should succeed")
        .expect("context state should exist");
    let mut context_state: AgentState =
        codec::from_bytes_canonical(&context_bytes).expect("context state should decode");
    context_state.status = AgentStatus::Completed(Some(
            "Likely files: path_utils.py\nTargeted checks: python3 -m unittest tests.test_path_utils -v"
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &context_key,
        &context_state,
        service.memory_runtime.as_ref(),
    )
    .expect("context state update should persist");

    let merged_context = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        3,
        0,
        &hex::encode(context.child_session_id),
    )
    .await
    .expect("context merge should advance to implement");
    assert!(merged_context.contains("advanced to 'Patch the workspace'"));

    let run_after_context =
        load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
            .expect("playbook run lookup should succeed")
            .expect("playbook run should exist");
    let implement_id = run_after_context
        .active_child_session_id
        .expect("implement child should be active");
    let implement_key = get_state_key(&implement_id);
    let implement_bytes = state
        .get(&implement_key)
        .expect("implement state lookup should succeed")
        .expect("implement state should exist");
    let mut implement_state: AgentState =
        codec::from_bytes_canonical(&implement_bytes).expect("implement state should decode");
    implement_state.status =
        AgentStatus::Failed("Agent Failure: Resources/Retry limit exceeded".to_string());
    persist_agent_state(
        &mut state,
        &implement_key,
        &implement_state,
        service.memory_runtime.as_ref(),
    )
    .expect("implement state update should persist");

    let blocked = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        4,
        0,
        &hex::encode(implement_id),
    )
    .await
    .expect("failed implement should block playbook");
    assert!(blocked.contains("blocked at 'Patch the workspace'"));

    let blocked_run =
        load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
            .expect("blocked playbook run lookup should succeed")
            .expect("blocked playbook run should exist");
    assert_eq!(blocked_run.status, ParentPlaybookStatus::Blocked);
    assert_eq!(
        blocked_run.steps[1].status,
        ParentPlaybookStepStatus::Blocked
    );

    let replay_context = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x62; 32],
        "Capture context for the patch task.",
        96,
        Some("evidence_audited_patch"),
        Some("context_worker"),
        Some("repo_context_brief"),
        None,
        None,
        None,
        None,
        5,
        0,
    )
    .await
    .expect("replayed context step should spawn");

    let run_after_replay_spawn =
        load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
            .expect("replayed playbook run lookup should succeed")
            .expect("replayed playbook run should exist");
    assert_eq!(run_after_replay_spawn.status, ParentPlaybookStatus::Running);
    assert_eq!(
        run_after_replay_spawn.steps[0].status,
        ParentPlaybookStepStatus::Running
    );
    assert_eq!(
        run_after_replay_spawn.steps[1].status,
        ParentPlaybookStepStatus::Pending
    );
    assert_eq!(
        run_after_replay_spawn.steps[2].status,
        ParentPlaybookStepStatus::Pending
    );
    assert_eq!(
        run_after_replay_spawn.steps[3].status,
        ParentPlaybookStepStatus::Pending
    );
    assert!(run_after_replay_spawn.completed_at_ms.is_none());

    let replay_context_key = get_state_key(&replay_context.child_session_id);
    let replay_context_bytes = state
        .get(&replay_context_key)
        .expect("replayed context state lookup should succeed")
        .expect("replayed context state should exist");
    let mut replay_context_state: AgentState = codec::from_bytes_canonical(&replay_context_bytes)
        .expect("replayed context state should decode");
    replay_context_state.status = AgentStatus::Completed(Some(
            "Likely files: path_utils.py\nTargeted checks: python3 -m unittest tests.test_path_utils -v"
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &replay_context_key,
        &replay_context_state,
        service.memory_runtime.as_ref(),
    )
    .expect("replayed context state update should persist");

    let merged_replay = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        6,
        0,
        &hex::encode(replay_context.child_session_id),
    )
    .await
    .expect("replayed context merge should advance to implement again");
    assert!(
        merged_replay.contains("advanced to 'Patch the workspace'"),
        "unexpected replay merge output: {merged_replay}"
    );
    assert!(
        !merged_replay.contains("completed."),
        "replayed context should not complete the playbook: {merged_replay}"
    );

    let final_run =
        load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
            .expect("final playbook run lookup should succeed")
            .expect("final playbook run should exist");
    assert_eq!(final_run.status, ParentPlaybookStatus::Running);
    assert_eq!(
        final_run.steps[0].status,
        ParentPlaybookStepStatus::Completed
    );
    assert_eq!(final_run.steps[1].status, ParentPlaybookStepStatus::Running);
    assert!(final_run.completed_at_ms.is_none());
}
