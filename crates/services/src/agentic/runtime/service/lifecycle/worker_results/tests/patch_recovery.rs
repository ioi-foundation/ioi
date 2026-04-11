use super::*;

#[test]
fn evidence_audited_patch_injects_raw_implement_handoff_into_verifier_goal() {
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic = "Port the path-normalization parity fix into the kernel-managed control plane.";
    let parent_state = build_parent_state_with_goal(topic, 160);
    let playbook = builtin_agent_playbook(Some("evidence_audited_patch"))
        .expect("coding parent playbook should exist");
    let mut run = build_parent_playbook_run(&parent_state, &playbook, 42);

    run.steps[0].status = ParentPlaybookStepStatus::Completed;
    run.steps[0].output_preview = Some(
            "Likely files: path_utils.py; tests/test_path_utils.py | Targeted checks: python3 -m unittest tests.test_path_utils -v"
                .to_string(),
        );
    run.steps[0].completed_at_ms = Some(43);

    let implement_id = [0x62; 32];
    run.steps[1].status = ParentPlaybookStepStatus::Completed;
    run.steps[1].child_session_id = Some(implement_id);
    run.steps[1].output_preview = Some(
            "Touched files: path_utils.py | Verification: python3 -m unittest tests.test_path_utils -v (passed)"
                .to_string(),
        );
    run.steps[1].completed_at_ms = Some(44);

    persist_worker_session_result(
            &mut state,
            &crate::agentic::runtime::types::WorkerSessionResult {
                child_session_id: implement_id,
                parent_session_id: parent_state.session_id,
                budget: 64,
                playbook_id: Some("evidence_audited_patch".to_string()),
                template_id: Some("coder".to_string()),
                workflow_id: Some("patch_build_verify".to_string()),
                role: "coder".to_string(),
                goal: format!("Implement {}", topic),
                status: "completed".to_string(),
                success: true,
                error: None,
                raw_output: Some(
                    "Touched files: path_utils.py\nVerification: python3 -m unittest tests.test_path_utils -v (passed)\nResidual risk: Focused verification passed; broader checks were not rerun."
                        .to_string(),
                ),
                merged_output: "Touched files: path_utils.py".to_string(),
                completion_contract: WorkerCompletionContract::default(),
                completed_at_ms: 44,
                merged_at_ms: Some(44),
                merged_step_index: Some(1),
            },
        )
        .expect("implement handoff should persist");

    let verify_step = &playbook.steps[2];
    let goal = inject_parent_playbook_context(
        &state,
        &verify_step.goal_template.replace("{topic}", topic),
        &playbook,
        &run,
        verify_step,
    );

    assert!(goal.contains(PARENT_PLAYBOOK_CONTEXT_MARKER));
    assert!(goal.contains("Likely files: path_utils.py"));
    assert!(goal.contains("Patch the workspace full_handoff (implement_full):"));
    assert!(goal.contains("Touched files: path_utils.py"));
    assert!(goal.contains("Verification: python3 -m unittest tests.test_path_utils -v (passed)"));
    assert!(
        goal.contains("Residual risk: Focused verification passed; broader checks were not rerun.")
    );
}

#[test]
fn materialize_patch_build_verify_result_enriches_summary_only_completion() {
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let parent_state = build_parent_state_with_goal("Patch the path normalizer.", 128);
    let child_session_id = [0x63; 32];
    let assignment = resolve_worker_assignment(
            child_session_id,
            4,
            64,
            "Implement the path normalizer fix in \"/tmp/fixture\". Run `python3 -m unittest tests.test_path_utils -v` first, widen only if needed, and return touched files plus command results.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v",
            Some("evidence_audited_patch"),
            Some("coder"),
            Some("patch_build_verify"),
            None,
            None,
            None,
            None,
        );
    persist_worker_assignment(&mut state, child_session_id, &assignment)
        .expect("assignment should persist");

    let mut child_state = build_parent_state();
    child_state.session_id = child_session_id;
    child_state.parent_session_id = Some(parent_state.session_id);
    child_state.goal = assignment.goal.clone();
    child_state.status = AgentStatus::Completed(Some(
            "Successfully implemented and verified the path-normalization parity fix in 'path_utils.py'. The focused verification command passed all tests without issues.".to_string(),
        ));
    child_state
        .command_history
        .push_back(crate::agentic::runtime::types::CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 0,
            stdout: String::new(),
            stderr: "OK".to_string(),
            timestamp_ms: 1,
            step_index: 7,
        });
    child_state.tool_execution_log.insert(
        "receipt::workspace_edit_applied=true".to_string(),
        crate::agentic::runtime::types::ToolCallStatus::Executed(
            "step=6;tool=file__write;path=path_utils.py".to_string(),
        ),
    );

    let result =
        materialize_worker_result(&mut state, &child_state).expect("result should materialize");

    let raw_output = result.raw_output.expect("raw output should be present");
    assert!(raw_output.contains("Touched files: path_utils.py"));
    assert!(
        raw_output.contains("Verification: python3 -m unittest tests.test_path_utils -v (passed)")
    );
    assert!(raw_output
        .contains("Residual risk: Focused verification passed; broader checks were not rerun."));
    assert!(raw_output.contains(
            "Summary: Successfully implemented and verified the path-normalization parity fix in 'path_utils.py'."
        ));
}

#[test]
fn synthesize_observed_patch_build_verify_completion_recovers_running_child_after_successful_rerun()
{
    let repo_root = std::path::PathBuf::from("/tmp/fixture");
    let source_path = repo_root.join("path_utils.py");
    let child_session_id = [0x65; 32];
    let assignment = resolve_worker_assignment(
            child_session_id,
            4,
            64,
            "Implement the path normalizer fix in \"/tmp/fixture\". Run `python3 -m unittest tests.test_path_utils -v` first, widen only if needed, and return touched files plus command results.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v",
            Some("evidence_audited_patch"),
            Some("coder"),
            Some("patch_build_verify"),
            None,
            None,
            None,
            None,
        );

    let mut child_state = build_parent_state();
    child_state.session_id = child_session_id;
    child_state.parent_session_id = Some([0x66; 32]);
    child_state.goal = assignment.goal.clone();
    child_state.working_directory = repo_root.to_string_lossy().to_string();
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
        "receipt::workspace_edit_applied=true".to_string(),
        crate::agentic::runtime::types::ToolCallStatus::Executed(format!(
            "step=4;tool=file__write;path={}",
            source_path.display()
        )),
    );

    let summary = synthesize_observed_patch_build_verify_completion(&child_state, &assignment)
        .expect("observed running completion should synthesize");

    assert!(
        summary.contains("Touched files: path_utils.py"),
        "{summary}"
    );
    assert!(
        summary.contains("Verification: python3 -m unittest tests.test_path_utils -v (passed)"),
        "{summary}"
    );
    assert!(summary.contains("Residual risk:"), "{summary}");
}

#[test]
fn materialize_patch_synthesis_completion_recovers_from_parent_receipts() {
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let parent_state = build_parent_state_with_goal("Patch the path normalizer.", 128);
    let playbook = builtin_agent_playbook(Some("evidence_audited_patch"))
        .expect("coding playbook should exist");
    let mut run = build_parent_playbook_run(&parent_state, &playbook, 1);
    let implement_id = [0x71; 32];
    let verify_id = [0x72; 32];

    run.current_step_index = 3;
    run.steps[1].status = ParentPlaybookStepStatus::Completed;
    run.steps[1].child_session_id = Some(implement_id);
    run.steps[2].status = ParentPlaybookStepStatus::Completed;
    run.steps[2].child_session_id = Some(verify_id);
    run.steps[2].coding_scorecard = Some(CodingVerificationScorecard {
        verdict: "passed".to_string(),
        targeted_command_count: 1,
        targeted_pass_count: 1,
        widening_status: "not_needed".to_string(),
        regression_status: "clear".to_string(),
        notes: Some("Focused unittest verification passed without widening.".to_string()),
    });
    persist_parent_playbook_run(&mut state, &run).expect("parent playbook run should persist");

    persist_worker_session_result(
            &mut state,
            &crate::agentic::runtime::types::WorkerSessionResult {
                child_session_id: implement_id,
                parent_session_id: parent_state.session_id,
                budget: 64,
                playbook_id: Some("evidence_audited_patch".to_string()),
                template_id: Some("coder".to_string()),
                workflow_id: Some("patch_build_verify".to_string()),
                role: "Coding Worker".to_string(),
                goal: "Implement the path normalizer fix.".to_string(),
                status: "Completed".to_string(),
                success: true,
                error: None,
                raw_output: Some(
                    "Touched files: path_utils.py\nVerification: python3 -m unittest tests.test_path_utils -v (passed)\nResidual risk: Focused verification passed; broader checks were not rerun.".to_string(),
                ),
                merged_output: "Coding Worker completed delegated work: touched files and verification recorded.".to_string(),
                completion_contract: WorkerCompletionContract::default(),
                completed_at_ms: 2,
                merged_at_ms: None,
                merged_step_index: None,
            },
        )
        .expect("implement worker result should persist");

    let child_session_id = [0x73; 32];
    let assignment = resolve_worker_assignment(
        child_session_id,
        6,
        40,
        "Synthesize the verified patch for the path normalizer into a final handoff.",
        Some("evidence_audited_patch"),
        Some("patch_synthesizer"),
        Some("patch_synthesis_handoff"),
        None,
        None,
        None,
        None,
    );
    persist_worker_assignment(&mut state, child_session_id, &assignment)
        .expect("assignment should persist");

    let mut child_state = build_parent_state();
    child_state.session_id = child_session_id;
    child_state.parent_session_id = Some(parent_state.session_id);
    child_state.goal = assignment.goal.clone();
    child_state.status = AgentStatus::Completed(None);

    let result =
        materialize_worker_result(&mut state, &child_state).expect("result should materialize");

    assert!(result.success);
    let raw_output = result.raw_output.expect("raw output should be present");
    assert!(raw_output.contains("- status: ready"), "{raw_output}");
    assert!(
        raw_output.contains("- touched_file_count: 1"),
        "{raw_output}"
    );
    assert!(
        raw_output.contains("- verification_ready: yes"),
        "{raw_output}"
    );
    assert!(
        raw_output.contains("Focused unittest verification passed without widening."),
        "{raw_output}"
    );
    assert!(
        raw_output.contains("Focused verification passed; broader checks were not rerun."),
        "{raw_output}"
    );
}

#[test]
fn patch_build_verify_post_edit_followup_uses_failed_command_history_without_goal_literal() {
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let parent_state = build_parent_state_with_goal("Patch the path normalizer.", 128);
    let child_session_id = [0x64; 32];
    let assignment = resolve_worker_assignment(
            child_session_id,
            4,
            64,
            "Implement the path normalizer fix in \"/tmp/fixture\" and return touched files plus command results.\n\n[PARENT PLAYBOOK CONTEXT]\n- Capture repo context (context): Worker evidence\nRole: Context Worker\nGoal: Inspect repo context for the path normalizer fix.",
            Some("evidence_audited_patch"),
            Some("coder"),
            Some("patch_build_verify"),
            None,
            None,
            None,
            None,
        );
    persist_worker_assignment(&mut state, child_session_id, &assignment)
        .expect("assignment should persist");

    let mut child_state = build_parent_state();
    child_state.session_id = child_session_id;
    child_state.parent_session_id = Some(parent_state.session_id);
    child_state.goal = assignment.goal.clone();
    child_state
        .command_history
        .push_back(crate::agentic::runtime::types::CommandExecution {
            command: "python3 -m unittest tests.test_path_utils -v".to_string(),
            exit_code: 1,
            stdout: String::new(),
            stderr: "FAIL".to_string(),
            timestamp_ms: 1,
            step_index: 2,
        });
    child_state.tool_execution_log.insert(
        "receipt::workspace_edit_applied=true".to_string(),
        crate::agentic::runtime::types::ToolCallStatus::Executed(
            "step=5;tool=file__write;path=path_utils.py".to_string(),
        ),
    );

    assert_eq!(
        latest_failed_goal_command_step(&child_state, &assignment),
        Some(2)
    );
    assert!(patch_build_verify_post_edit_followup_due(
        &child_state,
        &assignment
    ));
    assert_eq!(
        await_child_burst_step_limit(&state, child_session_id, &child_state)
            .expect("burst limit should resolve"),
        MAX_AWAIT_CHILD_BURST_STEPS + PATCH_BUILD_VERIFY_POST_EDIT_BURST_GRACE_STEPS
    );
}
