use super::*;

#[tokio::test(flavor = "current_thread")]
async fn artifact_generation_gate_surfaces_context_generation_and_quality_receipts() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(64);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic =
            "Generate a launch landing page artifact and verify the retained HTML is ready for presentation.";
    let preview_assignment = resolve_worker_assignment(
        [0x81; 32],
        13,
        96,
        topic,
        Some("artifact_generation_gate"),
        Some("context_worker"),
        Some("artifact_context_brief"),
        None,
        None,
        None,
        None,
    );
    let retrieval_anchor = format!(
            "{} Prior note: strong artifact runs keep the hero contrast crisp and the mobile CTA stack stable.",
            preview_assignment.goal
        );
    seed_runtime_artifact_skill(&service, &mut state, &preview_assignment.goal).await;
    seed_runtime_fact(&service, &retrieval_anchor).await;

    let mut parent_state = build_parent_state_with_goal(topic, 320);
    let context = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x82; 32],
        topic,
        196,
        Some("artifact_generation_gate"),
        Some("context_worker"),
        Some("artifact_context_brief"),
        None,
        None,
        None,
        None,
        13,
        0,
    )
    .await
    .expect("artifact context step should spawn");
    let context_id = context.child_session_id;
    assert_eq!(
        context.assignment.workflow_id.as_deref(),
        Some("artifact_context_brief")
    );

    let run_after_spawn =
        load_parent_playbook_run(&state, parent_state.session_id, "artifact_generation_gate")
            .expect("artifact playbook run lookup should succeed")
            .expect("artifact playbook run should exist");
    assert_eq!(
        run_after_spawn.steps[0].status,
        ParentPlaybookStepStatus::Running
    );
    assert!(run_after_spawn.steps[0]
        .selected_skills
        .iter()
        .any(|skill| skill == "artifact__frontend_judge_spine"));
    assert!(run_after_spawn.steps[0]
        .prep_summary
        .as_deref()
        .map(str::trim)
        .is_some_and(|summary| !summary.is_empty()));

    let context_key = get_state_key(&context_id);
    let context_bytes = state
        .get(&context_key)
        .expect("context state lookup should succeed")
        .expect("context state should exist");
    let mut context_state: AgentState =
        codec::from_bytes_canonical(&context_bytes).expect("context state should decode");
    context_state.status = AgentStatus::Completed(Some(
            "- artifact_goal: Bold editorial landing page with a clear launch narrative.\n- likely_output_files: apps/site/index.html; apps/site/styles.css\n- selected_skills: artifact__frontend_judge_spine\n- verification_plan: Check runtime/mobile hierarchy, hero contrast, and CTA visibility.\n- notes: Keep motion restrained and typography expressive."
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
        14,
        0,
        &hex::encode(context_id),
    )
    .await
    .expect("context merge should advance artifact playbook");
    assert!(merged_context.contains("Playbook: Artifact Context Brief (artifact_context_brief)"));
    assert!(merged_context.contains("advanced to 'Generate artifact'"));

    let run_after_context =
        load_parent_playbook_run(&state, parent_state.session_id, "artifact_generation_gate")
            .expect("artifact playbook run lookup should succeed")
            .expect("artifact playbook run should exist");
    assert_eq!(
        run_after_context.steps[0].status,
        ParentPlaybookStepStatus::Completed
    );
    assert_eq!(
        run_after_context.steps[1].status,
        ParentPlaybookStepStatus::Running
    );
    let build_id = run_after_context
        .active_child_session_id
        .expect("artifact builder should be active");

    let build_key = get_state_key(&build_id);
    let build_bytes = state
        .get(&build_key)
        .expect("build state lookup should succeed")
        .expect("build state should exist");
    let mut build_state: AgentState =
        codec::from_bytes_canonical(&build_bytes).expect("build state should decode");
    assert!(build_state.goal.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
    assert!(build_state.goal.contains("artifact__frontend_judge_spine"));
    build_state.status = AgentStatus::Completed(Some(
            "- produced_files: apps/site/index.html; apps/site/styles.css\n- verification_signals: Preview build passed; responsive screenshot captured.\n- presentation_status: needs_repair\n- repair_status: required\n- notes: Mobile hero copy overlaps the CTA at the narrow breakpoint."
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &build_key,
        &build_state,
        service.memory_runtime.as_ref(),
    )
    .expect("build state update should persist");

    let merged_build = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        15,
        0,
        &hex::encode(build_id),
    )
    .await
    .expect("build merge should advance artifact playbook");
    assert!(
        merged_build.contains("Playbook: Artifact Generate and Repair (artifact_generate_repair)")
    );
    assert!(merged_build.contains("advanced to 'Judge artifact quality'"));

    let run_after_build =
        load_parent_playbook_run(&state, parent_state.session_id, "artifact_generation_gate")
            .expect("artifact playbook run lookup should succeed")
            .expect("artifact playbook run should exist");
    assert_eq!(
        run_after_build.steps[1].status,
        ParentPlaybookStepStatus::Completed
    );
    assert_eq!(
        run_after_build.steps[1]
            .artifact_generation
            .as_ref()
            .map(|summary| summary.produced_file_count),
        Some(2)
    );
    assert_eq!(
        run_after_build.steps[1]
            .artifact_repair
            .as_ref()
            .map(|summary| summary.status.as_str()),
        Some("required")
    );
    assert_eq!(
        run_after_build.steps[2].status,
        ParentPlaybookStepStatus::Running
    );
    let judge_id = run_after_build
        .active_child_session_id
        .expect("artifact judge should be active");

    let judge_key = get_state_key(&judge_id);
    let judge_bytes = state
        .get(&judge_key)
        .expect("judge state lookup should succeed")
        .expect("judge state should exist");
    let mut judge_state: AgentState =
        codec::from_bytes_canonical(&judge_bytes).expect("judge state should decode");
    assert!(judge_state.goal.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
    assert!(judge_state.goal.contains("artifact_generation="));
    judge_state.status = AgentStatus::Completed(Some(
            "- verdict: needs_attention\n- fidelity_status: faithful\n- presentation_status: needs_repair\n- repair_status: required\n- next_repair_step: Fix the mobile hero stacking before presentation.\n- notes: Layout intent is strong, but mobile CTA overlap blocks presentation readiness."
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &judge_key,
        &judge_state,
        service.memory_runtime.as_ref(),
    )
    .expect("judge state update should persist");

    let merged_judge = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        16,
        0,
        &hex::encode(judge_id),
    )
    .await
    .expect("judge merge should complete artifact playbook");
    assert!(merged_judge.contains("Playbook: Artifact Quality Audit (artifact_quality_audit)"));
    assert!(merged_judge.contains("Parent playbook 'Artifact Generation Gate' completed."));

    let final_run =
        load_parent_playbook_run(&state, parent_state.session_id, "artifact_generation_gate")
            .expect("final artifact playbook run lookup should succeed")
            .expect("final artifact playbook run should exist");
    assert_eq!(final_run.status, ParentPlaybookStatus::Completed);
    assert!(final_run
        .steps
        .iter()
        .all(|step| step.status == ParentPlaybookStepStatus::Completed));
    assert_eq!(
        final_run.steps[2]
            .artifact_quality
            .as_ref()
            .map(|scorecard| scorecard.verdict.as_str()),
        Some("needs_attention")
    );
    assert_eq!(
        final_run.steps[2]
            .artifact_repair
            .as_ref()
            .map(|summary| summary.status.as_str()),
        Some("required")
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
        .all(|receipt| receipt.route_family == "artifacts"));
    assert!(parent_receipts
        .iter()
        .all(|receipt| receipt.planner_authority == "kernel"));
    assert!(parent_receipts
        .iter()
        .all(|receipt| receipt.verifier_role == "artifact_quality_verifier"));
    assert_eq!(
        parent_receipts
            .iter()
            .find(|receipt| {
                receipt.phase == "step_spawned" && receipt.step_id.as_deref() == Some("context")
            })
            .map(|receipt| receipt.selected_skills.clone())
            .unwrap_or_default(),
        vec!["artifact__frontend_judge_spine".to_string()]
    );
    assert_eq!(
        parent_receipts
            .iter()
            .find(|receipt| {
                receipt.phase == "step_completed" && receipt.step_id.as_deref() == Some("build")
            })
            .and_then(|receipt| receipt.artifact_generation.as_ref())
            .map(|summary| summary.produced_file_count),
        Some(2)
    );
    assert_eq!(
        parent_receipts
            .iter()
            .find(|receipt| {
                receipt.phase == "step_completed" && receipt.step_id.as_deref() == Some("judge")
            })
            .and_then(|receipt| receipt.artifact_quality.as_ref())
            .map(|scorecard| scorecard.presentation_status.as_str()),
        Some("needs_repair")
    );
    assert_eq!(
        parent_receipts
            .last()
            .map(|receipt| receipt.selected_skills.clone())
            .unwrap_or_default(),
        vec!["artifact__frontend_judge_spine".to_string()]
    );
    assert!(parent_receipts
        .last()
        .and_then(|receipt| receipt.prep_summary.as_deref())
        .map(str::trim)
        .is_some_and(|summary| !summary.is_empty()));
    assert_eq!(
        parent_receipts
            .last()
            .and_then(|receipt| receipt.artifact_repair.as_ref())
            .map(|summary| summary.status.as_str()),
        Some("required")
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
        Some("warning")
    );
}
