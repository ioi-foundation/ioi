use super::*;

#[tokio::test(flavor = "current_thread")]
async fn delegated_research_playbook_flows_through_spawn_and_merge_receipts() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(16);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let mut parent_state = build_parent_state();

    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x44; 32],
        "Research the latest kernel scheduler benchmarks.",
        2,
        None,
        Some("researcher"),
        Some("live_research_brief"),
        None,
        None,
        None,
        None,
        3,
        0,
    )
    .await
    .expect("delegated child should spawn");
    let child_session_id = spawned.child_session_id;
    assert_eq!(spawned.assignment.budget, 2);
    assert_eq!(
        spawned.assignment.workflow_id.as_deref(),
        Some("live_research_brief")
    );

    let child_key = get_state_key(&child_session_id);
    let child_bytes = state
        .get(&child_key)
        .expect("child state lookup should succeed")
        .expect("child state should exist");
    let mut child_state: AgentState =
        codec::from_bytes_canonical(&child_bytes).expect("child state should decode");
    assert!(child_state
        .goal
        .contains("using current web and local memory evidence"));

    child_state.status = AgentStatus::Completed(Some(
        "Cited brief with three benchmark sources and one unresolved discrepancy.".to_string(),
    ));
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
        4,
        0,
        &hex::encode(child_session_id),
    )
    .await
    .expect("await result should merge");

    assert!(merged.contains("Playbook: Live Research Brief (live_research_brief)"));
    assert!(merged.contains("Cited brief with three benchmark sources"));

    let mut completion_saw_workflow = false;
    let mut merge_saw_workflow = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            if let WorkloadReceipt::Worker(receipt) = receipt_event.receipt {
                match receipt.phase.as_str() {
                    "completed" => {
                        assert_eq!(receipt.workflow_id.as_deref(), Some("live_research_brief"));
                        completion_saw_workflow = true;
                    }
                    "merged" => {
                        assert_eq!(receipt.workflow_id.as_deref(), Some("live_research_brief"));
                        merge_saw_workflow = true;
                    }
                    _ => {}
                }
            }
        }
    }

    assert!(
        completion_saw_workflow,
        "completion receipt should preserve workflow id"
    );
    assert!(
        merge_saw_workflow,
        "merge receipt should preserve workflow id"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn citation_grounded_brief_surfaces_selected_skills_and_prep_summary() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(32);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic = "Research the latest kernel scheduler benchmark scorecards.";
    let preview_assignment = resolve_worker_assignment(
        [0x71; 32],
        2,
        64,
        topic,
        Some("citation_grounded_brief"),
        Some("researcher"),
        Some("live_research_brief"),
        None,
        None,
        None,
        None,
    );
    let retrieval_anchor = format!(
            "{} Prior note: planner-specialist-verifier routing improved citation coverage on the last comparison pass.",
            preview_assignment.goal
        );
    seed_runtime_skill(&service, &mut state, &preview_assignment.goal).await;
    seed_runtime_fact(&service, &retrieval_anchor).await;

    let mut parent_state = build_parent_state_with_goal(topic, 128);
    let spawned = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x72; 32],
        topic,
        64,
        Some("citation_grounded_brief"),
        Some("researcher"),
        Some("live_research_brief"),
        None,
        None,
        None,
        None,
        2,
        0,
    )
    .await
    .expect("research route should spawn");
    assert_eq!(
        spawned.assignment.playbook_id.as_deref(),
        Some("citation_grounded_brief")
    );
    assert_eq!(
        spawned.assignment.workflow_id.as_deref(),
        Some("live_research_brief")
    );

    let run = load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
        .expect("parent playbook load should succeed")
        .expect("parent playbook run should exist");
    assert_eq!(run.steps[0].status, ParentPlaybookStepStatus::Running);
    assert!(run.steps[0]
        .selected_skills
        .iter()
        .any(|skill| skill == "research__benchmark_scorecard"));
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
                        assert_eq!(receipt.playbook_id, "citation_grounded_brief");
                        assert!(receipt
                            .selected_skills
                            .iter()
                            .any(|skill| skill == "research__benchmark_scorecard"));
                        assert!(receipt
                            .prep_summary
                            .as_deref()
                            .map(str::trim)
                            .is_some_and(|summary| !summary.is_empty()));
                        saw_parent_started = true;
                    } else if receipt.phase == "step_spawned" {
                        assert_eq!(receipt.playbook_id, "citation_grounded_brief");
                        assert!(receipt
                            .selected_skills
                            .iter()
                            .any(|skill| skill == "research__benchmark_scorecard"));
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
        "research prep should emit a memory receipt"
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
async fn citation_grounded_brief_blocks_parent_playbook_on_failed_research_worker() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(32);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic = "Research the latest kernel scheduler benchmark scorecards.";
    let mut parent_state = build_parent_state_with_goal(topic, 128);

    let research = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x7a; 32],
        topic,
        64,
        Some("citation_grounded_brief"),
        Some("researcher"),
        Some("live_research_brief"),
        None,
        None,
        None,
        None,
        2,
        0,
    )
    .await
    .expect("research route should spawn");
    let research_id = research.child_session_id;

    let research_key = get_state_key(&research_id);
    let research_bytes = state
        .get(&research_key)
        .expect("research state lookup should succeed")
        .expect("research state should exist");
    let mut research_state: AgentState =
        codec::from_bytes_canonical(&research_bytes).expect("research state should decode");
    research_state.status = AgentStatus::Failed(
        "Agent Failure: ERROR_CLASS=TimeoutOrHang Cognition inference timed out after 60000ms."
            .to_string(),
    );
    persist_agent_state(
        &mut state,
        &research_key,
        &research_state,
        service.memory_runtime.as_ref(),
    )
    .expect("research state update should persist");

    let blocked = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        3,
        0,
        &hex::encode(research_id),
    )
    .await
    .expect("failed research worker should block playbook instead of pausing parent");

    assert!(blocked.contains("Parent playbook 'Citation-Grounded Brief' blocked"));
    assert!(blocked.contains("Cognition inference timed out after 60000ms"));

    let run_after_research =
        load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
            .expect("research playbook run lookup should succeed")
            .expect("research playbook run should exist");
    assert_eq!(run_after_research.status, ParentPlaybookStatus::Blocked);
    assert_eq!(
        run_after_research.steps[0].status,
        ParentPlaybookStepStatus::Blocked
    );
    assert!(run_after_research.active_child_session_id.is_none());
    assert_eq!(
        run_after_research.steps[0].error.as_deref(),
        Some(
            "Agent Failure: ERROR_CLASS=TimeoutOrHang Cognition inference timed out after 60000ms."
        )
    );
    assert!(matches!(
        &parent_state.status,
        AgentStatus::Failed(reason)
            if reason.contains("Cognition inference timed out after 60000ms")
    ));

    let mut saw_worker_merge = false;
    let mut saw_playbook_blocked = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            match receipt_event.receipt {
                WorkloadReceipt::Worker(receipt) if receipt.phase == "merged" => {
                    assert_eq!(receipt.workflow_id.as_deref(), Some("live_research_brief"));
                    assert!(!receipt.success);
                    saw_worker_merge = true;
                }
                WorkloadReceipt::ParentPlaybook(receipt) if receipt.phase == "blocked" => {
                    assert_eq!(receipt.playbook_id, "citation_grounded_brief");
                    assert_eq!(receipt.workflow_id.as_deref(), Some("live_research_brief"));
                    assert_eq!(receipt.error_class.as_deref(), Some("TimeoutOrHang"));
                    saw_playbook_blocked = true;
                }
                _ => {}
            }
        }
    }

    assert!(
        saw_worker_merge,
        "failed worker should still emit a merge receipt"
    );
    assert!(
        saw_playbook_blocked,
        "parent playbook should emit a blocked receipt"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn citation_grounded_brief_blocks_parent_playbook_on_empty_research_handoff() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(32);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic = "Research the latest kernel scheduler benchmark scorecards.";
    let mut parent_state = build_parent_state_with_goal(topic, 128);

    let research = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x7c; 32],
        topic,
        64,
        Some("citation_grounded_brief"),
        Some("researcher"),
        Some("live_research_brief"),
        None,
        None,
        None,
        None,
        2,
        0,
    )
    .await
    .expect("research route should spawn");
    let research_id = research.child_session_id;

    let research_key = get_state_key(&research_id);
    let research_bytes = state
        .get(&research_key)
        .expect("research state lookup should succeed")
        .expect("research state should exist");
    let mut research_state: AgentState =
        codec::from_bytes_canonical(&research_bytes).expect("research state should decode");
    research_state.status = AgentStatus::Completed(None);
    persist_agent_state(
        &mut state,
        &research_key,
        &research_state,
        service.memory_runtime.as_ref(),
    )
    .expect("research state update should persist");

    let blocked = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        3,
        0,
        &hex::encode(research_id),
    )
    .await
    .expect("empty research handoff should block playbook");

    assert!(blocked.contains("Parent playbook 'Citation-Grounded Brief' blocked"));
    assert!(blocked.contains("IncompleteWorkerResult"));

    let run_after_research =
        load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
            .expect("research playbook run lookup should succeed")
            .expect("research playbook run should exist");
    assert_eq!(run_after_research.status, ParentPlaybookStatus::Blocked);
    assert_eq!(
        run_after_research.steps[0].status,
        ParentPlaybookStepStatus::Blocked
    );
    assert!(run_after_research.active_child_session_id.is_none());
    assert_eq!(
            run_after_research.steps[0].error.as_deref(),
            Some(
                "ERROR_CLASS=IncompleteWorkerResult Delegated worker completed without an explicit result."
            )
        );
    assert!(matches!(
        &parent_state.status,
        AgentStatus::Failed(reason) if reason.contains("IncompleteWorkerResult")
    ));

    let mut saw_worker_merge = false;
    let mut saw_playbook_blocked = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            match receipt_event.receipt {
                WorkloadReceipt::Worker(receipt) if receipt.phase == "merged" => {
                    assert_eq!(receipt.workflow_id.as_deref(), Some("live_research_brief"));
                    assert!(!receipt.success);
                    assert_eq!(
                        receipt.error_class.as_deref(),
                        Some("IncompleteWorkerResult")
                    );
                    saw_worker_merge = true;
                }
                WorkloadReceipt::ParentPlaybook(receipt) if receipt.phase == "blocked" => {
                    assert_eq!(receipt.playbook_id, "citation_grounded_brief");
                    assert_eq!(receipt.workflow_id.as_deref(), Some("live_research_brief"));
                    assert_eq!(
                        receipt.error_class.as_deref(),
                        Some("IncompleteWorkerResult")
                    );
                    saw_playbook_blocked = true;
                }
                _ => {}
            }
        }
    }

    assert!(
        saw_worker_merge,
        "empty worker handoff should still emit a merge receipt"
    );
    assert!(
        saw_playbook_blocked,
        "parent playbook should emit a blocked receipt for empty worker handoff"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn citation_grounded_brief_blocks_parent_playbook_on_system_fail_verifier_worker() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(32);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic = "Research the latest kernel scheduler benchmark scorecards.";
    let mut parent_state = build_parent_state_with_goal(topic, 128);

    let research = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x7b; 32],
        topic,
        64,
        Some("citation_grounded_brief"),
        Some("researcher"),
        Some("live_research_brief"),
        None,
        None,
        None,
        None,
        2,
        0,
    )
    .await
    .expect("research route should spawn");
    let research_id = research.child_session_id;

    let research_key = get_state_key(&research_id);
    let research_bytes = state
        .get(&research_key)
        .expect("research state lookup should succeed")
        .expect("research state should exist");
    let mut research_state: AgentState =
        codec::from_bytes_canonical(&research_bytes).expect("research state should decode");
    research_state.status = AgentStatus::Completed(Some(
            "Findings:\n- Linux 6.9 scheduler latency improved in recent tests.\nSources:\n- https://www.kernel.org/doc/html/latest/scheduler/index.html\n- https://lwn.net/Articles/123456/\nFreshness note: checked on 2026-03-31."
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &research_key,
        &research_state,
        service.memory_runtime.as_ref(),
    )
    .expect("research state update should persist");

    let merged_research = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        3,
        0,
        &hex::encode(research_id),
    )
    .await
    .expect("research merge should advance playbook");
    assert!(merged_research.contains("advanced to 'Verify grounding'"));

    let run_after_research =
        load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
            .expect("research playbook run lookup should succeed")
            .expect("research playbook run should exist");
    let verify_id = run_after_research
        .active_child_session_id
        .expect("citation verifier should be active");

    let verify_key = get_state_key(&verify_id);
    let verify_bytes = state
        .get(&verify_key)
        .expect("verifier state lookup should succeed")
        .expect("verifier state should exist");
    let mut verify_state: AgentState =
        codec::from_bytes_canonical(&verify_bytes).expect("verifier state should decode");
    verify_state.status = AgentStatus::Failed(
        "Agent Failure: ERROR_CLASS=TimeoutOrHang Cognition inference timed out after 60000ms."
            .to_string(),
    );
    persist_agent_state(
        &mut state,
        &verify_key,
        &verify_state,
        service.memory_runtime.as_ref(),
    )
    .expect("verifier state update should persist");

    let blocked = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        4,
        0,
        &hex::encode(verify_id),
    )
    .await
    .expect("failed verifier should block playbook");

    assert!(blocked.contains("Parent playbook 'Citation-Grounded Brief' blocked"));
    assert!(blocked.contains("Cognition inference timed out after 60000ms"));

    let final_run =
        load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
            .expect("final playbook run lookup should succeed")
            .expect("final playbook run should exist");
    assert_eq!(final_run.status, ParentPlaybookStatus::Blocked);
    assert_eq!(final_run.steps[1].status, ParentPlaybookStepStatus::Blocked);
    assert_eq!(
        final_run.steps[1].error.as_deref(),
        Some(
            "Agent Failure: ERROR_CLASS=TimeoutOrHang Cognition inference timed out after 60000ms."
        )
    );
    assert!(matches!(
        &parent_state.status,
        AgentStatus::Failed(reason)
            if reason.contains("Cognition inference timed out after 60000ms")
    ));

    let mut saw_worker_merge = false;
    let mut saw_playbook_blocked = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            match receipt_event.receipt {
                WorkloadReceipt::Worker(receipt)
                    if receipt.phase == "merged"
                        && receipt.workflow_id.as_deref() == Some("citation_audit") =>
                {
                    assert!(!receipt.success);
                    saw_worker_merge = true;
                }
                WorkloadReceipt::ParentPlaybook(receipt)
                    if receipt.phase == "blocked"
                        && receipt.workflow_id.as_deref() == Some("citation_audit") =>
                {
                    assert_eq!(receipt.error_class.as_deref(), Some("TimeoutOrHang"));
                    saw_playbook_blocked = true;
                }
                _ => {}
            }
        }
    }

    assert!(
        saw_worker_merge,
        "failed verifier should emit a merge receipt"
    );
    assert!(
        saw_playbook_blocked,
        "failed verifier should emit a blocked playbook receipt"
    );
}
