use super::*;

#[tokio::test(flavor = "current_thread")]
async fn browser_postcondition_gate_surfaces_selected_skills_and_prep_summary() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(32);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic =
            "Inspect the billing flow, identify the next safe UI action, and call out approval risk before acting.";
    let preview_assignment = resolve_worker_assignment(
        [0x90; 32],
        7,
        96,
        topic,
        Some("browser_postcondition_gate"),
        Some("perception_worker"),
        Some("ui_state_brief"),
        None,
        None,
        None,
        None,
    );
    let retrieval_anchor = format!(
            "{} Prior note: reliable browser runs identify the active target and modal risk before clicking.",
            preview_assignment.goal
        );
    seed_runtime_computer_use_skill(&service, &mut state, &preview_assignment.goal).await;
    seed_runtime_fact(&service, &retrieval_anchor).await;

    let mut parent_state = build_parent_state_with_goal(topic, 192);
    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x91; 32],
        topic,
        160,
        Some("browser_postcondition_gate"),
        Some("perception_worker"),
        Some("ui_state_brief"),
        None,
        None,
        None,
        None,
        7,
        0,
    )
    .await
    .expect("computer-use perception step should spawn");
    assert_eq!(
        spawned.assignment.playbook_id.as_deref(),
        Some("browser_postcondition_gate")
    );
    assert_eq!(
        spawned.assignment.workflow_id.as_deref(),
        Some("ui_state_brief")
    );

    let run = load_parent_playbook_run(
        &state,
        parent_state.session_id,
        "browser_postcondition_gate",
    )
    .expect("browser playbook run lookup should succeed")
    .expect("browser playbook run should exist");
    assert_eq!(run.steps[0].status, ParentPlaybookStepStatus::Running);
    assert!(run.steps[0]
        .selected_skills
        .iter()
        .any(|skill| skill == "computer_use__ui_state_spine"));
    assert!(run.steps[0]
        .prep_summary
        .as_deref()
        .map(str::trim)
        .is_some_and(|summary| !summary.is_empty()));

    let mut saw_memory_receipt = false;
    let mut saw_parent_started = false;
    let mut saw_parent_step_spawn = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            match receipt_event.receipt {
                WorkloadReceipt::MemoryRetrieve(receipt) => {
                    assert_eq!(receipt.tool_name, "memory__search");
                    saw_memory_receipt = true;
                }
                WorkloadReceipt::ParentPlaybook(receipt) => {
                    if receipt.phase == "started" {
                        assert_eq!(receipt.playbook_id, "browser_postcondition_gate");
                        assert!(receipt
                            .selected_skills
                            .iter()
                            .any(|skill| skill == "computer_use__ui_state_spine"));
                        assert!(receipt
                            .prep_summary
                            .as_deref()
                            .map(str::trim)
                            .is_some_and(|summary| !summary.is_empty()));
                        saw_parent_started = true;
                    } else if receipt.phase == "step_spawned" {
                        assert_eq!(receipt.playbook_id, "browser_postcondition_gate");
                        assert!(receipt
                            .selected_skills
                            .iter()
                            .any(|skill| skill == "computer_use__ui_state_spine"));
                        assert!(receipt
                            .prep_summary
                            .as_deref()
                            .map(str::trim)
                            .is_some_and(|summary| !summary.is_empty()));
                        saw_parent_step_spawn = true;
                    }
                }
                _ => {}
            }
        }
    }

    assert!(
        saw_memory_receipt,
        "computer-use prep should emit a memory receipt"
    );
    assert!(
        saw_parent_started,
        "started receipt should carry selected skills and prep summary"
    );
    assert!(
        saw_parent_step_spawn,
        "step_spawned receipt should carry selected skills and prep summary"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn browser_postcondition_gate_surfaces_perception_and_recovery_receipts() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(64);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic =
        "Open the billing website, submit the confirmation form, and verify the receipt page.";
    let mut parent_state = build_parent_state_with_goal(topic, 240);

    let perception = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x61; 32],
        topic,
        160,
        Some("browser_postcondition_gate"),
        Some("perception_worker"),
        Some("ui_state_brief"),
        None,
        None,
        None,
        None,
        9,
        0,
    )
    .await
    .expect("perception step should spawn");
    let perception_id = perception.child_session_id;
    assert_eq!(
        perception.assignment.workflow_id.as_deref(),
        Some("ui_state_brief")
    );

    let perception_key = get_state_key(&perception_id);
    let perception_bytes = state
        .get(&perception_key)
        .expect("perception state lookup should succeed")
        .expect("perception state should exist");
    let mut perception_state: AgentState =
        codec::from_bytes_canonical(&perception_bytes).expect("perception state should decode");
    perception_state.status = AgentStatus::Completed(Some(
            "- surface_status: clear\n- ui_state: Checkout form is visible with the submit button enabled.\n- target: Submit order button\n- approval_risk: possible\n- next_action: Click submit order\n- notes: A confirmation dialog may appear after submit."
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &perception_key,
        &perception_state,
        service.memory_runtime.as_ref(),
    )
    .expect("perception state update should persist");

    let merged_perception = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        10,
        0,
        &hex::encode(perception_id),
    )
    .await
    .expect("perception merge should advance playbook");
    assert!(merged_perception.contains("Playbook: UI State Brief (ui_state_brief)"));
    assert!(merged_perception.contains("advanced to 'Execute in browser'"));

    let run_after_perception = load_parent_playbook_run(
        &state,
        parent_state.session_id,
        "browser_postcondition_gate",
    )
    .expect("browser playbook run lookup should succeed")
    .expect("browser playbook run should exist");
    assert_eq!(
        run_after_perception.steps[0].status,
        ParentPlaybookStepStatus::Completed
    );
    assert_eq!(
        run_after_perception.steps[0]
            .computer_use_perception
            .as_ref()
            .map(|summary| summary.surface_status.as_str()),
        Some("clear")
    );
    assert_eq!(
        run_after_perception.steps[1].status,
        ParentPlaybookStepStatus::Running
    );
    let execute_id = run_after_perception
        .active_child_session_id
        .expect("execute child should be active");

    let execute_key = get_state_key(&execute_id);
    let execute_bytes = state
        .get(&execute_key)
        .expect("execute state lookup should succeed")
        .expect("execute state should exist");
    let mut execute_state: AgentState =
        codec::from_bytes_canonical(&execute_bytes).expect("execute state should decode");
    assert!(execute_state.goal.contains("grounded observations first"));
    assert!(execute_state.goal.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
    execute_state.status = AgentStatus::Completed(Some(
            "- executed_steps: navigated to billing page; clicked submit order\n- observed_postcondition: Confirmation banner is visible and the URL changed to /receipt.\n- approval_state: approved\n- recovery_status: not_needed\n- next_recovery_step: Return completion to the parent planner.\n- blocker_summary: none\n- notes: Browser submit flow completed without needing fallback."
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &execute_key,
        &execute_state,
        service.memory_runtime.as_ref(),
    )
    .expect("execute state update should persist");

    let merged_execute = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        11,
        0,
        &hex::encode(execute_id),
    )
    .await
    .expect("execute merge should advance playbook");
    assert!(merged_execute
        .contains("Playbook: Browser Postcondition Pass (browser_postcondition_pass)"));
    assert!(merged_execute.contains("advanced to 'Verify postcondition'"));

    let run_after_execute = load_parent_playbook_run(
        &state,
        parent_state.session_id,
        "browser_postcondition_gate",
    )
    .expect("browser playbook run lookup should succeed")
    .expect("browser playbook run should exist");
    assert_eq!(
        run_after_execute.steps[1].status,
        ParentPlaybookStepStatus::Completed
    );
    assert_eq!(
        run_after_execute.steps[1]
            .computer_use_recovery
            .as_ref()
            .map(|summary| summary.status.as_str()),
        Some("not_needed")
    );
    assert_eq!(
        run_after_execute.steps[2].status,
        ParentPlaybookStepStatus::Running
    );
    let verify_id = run_after_execute
        .active_child_session_id
        .expect("verify child should be active");

    let verify_key = get_state_key(&verify_id);
    let verify_bytes = state
        .get(&verify_key)
        .expect("verify state lookup should succeed")
        .expect("verify state should exist");
    let mut verify_state: AgentState =
        codec::from_bytes_canonical(&verify_bytes).expect("verify state should decode");
    assert!(verify_state
        .goal
        .contains("computer-use verifier scorecard"));
    assert!(verify_state.goal.contains("computer_use_perception=clear"));
    verify_state.status = AgentStatus::Completed(Some(
            "- verdict: passed\n- postcondition_status: met\n- approval_state: approved\n- recovery_status: not_needed\n- notes: Confirmation banner and receipt URL match the requested postcondition."
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
        12,
        0,
        &hex::encode(verify_id),
    )
    .await
    .expect("verify merge should complete playbook");
    assert!(merged_verify
        .contains("Playbook: Browser Postcondition Audit (browser_postcondition_audit)"));
    assert!(merged_verify.contains("Parent playbook 'Browser Postcondition Gate' completed."));

    let final_run = load_parent_playbook_run(
        &state,
        parent_state.session_id,
        "browser_postcondition_gate",
    )
    .expect("final browser playbook run lookup should succeed")
    .expect("final browser playbook run should exist");
    assert_eq!(final_run.status, ParentPlaybookStatus::Completed);
    assert!(final_run
        .steps
        .iter()
        .all(|step| step.status == ParentPlaybookStepStatus::Completed));
    assert_eq!(
        final_run.steps[2]
            .computer_use_verification
            .as_ref()
            .map(|scorecard| scorecard.verdict.as_str()),
        Some("passed")
    );
    assert_eq!(
        final_run.steps[2]
            .computer_use_recovery
            .as_ref()
            .map(|summary| summary.status.as_str()),
        Some("not_needed")
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
            "completed".to_string(),
        ]
    );
    assert!(parent_receipts
        .iter()
        .all(|receipt| receipt.route_family == "computer_use"));
    assert!(parent_receipts
        .iter()
        .all(|receipt| receipt.planner_authority == "kernel"));
    assert!(parent_receipts
        .iter()
        .all(|receipt| receipt.verifier_role == "postcondition_verifier"));
    assert_eq!(
        parent_receipts
            .iter()
            .find(|receipt| {
                receipt.phase == "step_completed" && receipt.step_id.as_deref() == Some("perceive")
            })
            .and_then(|receipt| receipt.computer_use_perception.as_ref())
            .map(|summary| summary.surface_status.as_str()),
        Some("clear")
    );
    assert_eq!(
        parent_receipts
            .iter()
            .find(|receipt| {
                receipt.phase == "step_completed" && receipt.step_id.as_deref() == Some("verify")
            })
            .and_then(|receipt| receipt.computer_use_verification.as_ref())
            .map(|summary| summary.postcondition_status.as_str()),
        Some("met")
    );
    assert_eq!(
        parent_receipts
            .last()
            .and_then(|receipt| receipt.computer_use_recovery.as_ref())
            .map(|summary| summary.status.as_str()),
        Some("not_needed")
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
