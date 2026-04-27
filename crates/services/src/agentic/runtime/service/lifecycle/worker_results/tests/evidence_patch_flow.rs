use super::*;

#[tokio::test(flavor = "current_thread")]
async fn evidence_audited_patch_blocks_parent_playbook_on_paused_refusal_worker() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(32);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic = "Patch only the targeted repo file and verify the focused test first.";
    let mut parent_state = build_parent_state_with_goal(topic, 256);

    let context = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x63; 32],
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
        AgentStatus::Paused("Model Refusal: Empty content (reason: stop)".to_string());
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
    .expect("paused refusal worker should block parent playbook");

    assert!(blocked.contains("Parent playbook 'Evidence-Audited Patch' blocked"));
    assert!(blocked.contains("Patch the workspace"));
    assert!(blocked.contains("Model Refusal: Empty content (reason: stop)"));

    let blocked_run =
        load_parent_playbook_run(&state, parent_state.session_id, "evidence_audited_patch")
            .expect("blocked playbook run lookup should succeed")
            .expect("blocked playbook run should exist");
    assert_eq!(blocked_run.status, ParentPlaybookStatus::Blocked);
    assert_eq!(
        blocked_run.steps[1].status,
        ParentPlaybookStepStatus::Blocked
    );
    assert!(blocked_run.active_child_session_id.is_none());
    assert_eq!(
        blocked_run.steps[1].error.as_deref(),
        Some("ERROR_CLASS=UserInterventionNeeded Model Refusal: Empty content (reason: stop)")
    );
    assert!(matches!(
        &parent_state.status,
        AgentStatus::Paused(reason)
            if reason.contains("Model Refusal: Empty content (reason: stop)")
    ));

    let materialized = load_worker_session_result(&state, implement_id)
        .expect("worker result lookup should succeed");
    let materialized = materialized.expect("paused worker should materialize a result");
    assert_eq!(materialized.status, "Paused");
    assert!(!materialized.success);
    assert_eq!(
        materialized.error.as_deref(),
        Some("ERROR_CLASS=UserInterventionNeeded Model Refusal: Empty content (reason: stop)")
    );

    let mut saw_worker_merge = false;
    let mut saw_playbook_blocked = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            match receipt_event.receipt {
                WorkloadReceipt::Worker(receipt) if receipt.phase == "merged" => {
                    if receipt.child_session_id == hex::encode(implement_id) {
                        assert_eq!(receipt.workflow_id.as_deref(), Some("patch_build_verify"));
                        assert!(!receipt.success);
                        assert_eq!(receipt.status, "Paused");
                        assert_eq!(
                            receipt.error_class.as_deref(),
                            Some("UserInterventionNeeded")
                        );
                        saw_worker_merge = true;
                    }
                }
                WorkloadReceipt::ParentPlaybook(receipt) if receipt.phase == "blocked" => {
                    if receipt.playbook_id == "evidence_audited_patch" {
                        assert_eq!(receipt.workflow_id.as_deref(), Some("patch_build_verify"));
                        assert_eq!(
                            receipt.error_class.as_deref(),
                            Some("UserInterventionNeeded")
                        );
                        assert!(receipt
                            .prep_summary
                            .as_deref()
                            .map(str::trim)
                            .is_some_and(|summary| !summary.is_empty()));
                        saw_playbook_blocked = true;
                    }
                }
                _ => {}
            }
        }
    }

    assert!(
        saw_worker_merge,
        "paused worker should emit a merge receipt"
    );
    assert!(
        saw_playbook_blocked,
        "parent playbook should emit a blocked receipt for the paused worker"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn evidence_audited_patch_recovers_paused_refusal_worker_after_successful_verification() {
    let (tx, _rx) = tokio::sync::broadcast::channel(32);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic = "Patch only the targeted repo file and verify the focused test first.";
    let mut parent_state = build_parent_state_with_goal(topic, 256);

    let context = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x67; 32],
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
        AgentStatus::Paused("Model Refusal: Empty content (reason: length)".to_string());
    implement_state.command_history.push_back(CommandExecution {
        command: "python3 -m unittest tests.test_path_utils -v".to_string(),
        exit_code: 1,
        stdout: String::new(),
        stderr: "FAILED (failures=2)".to_string(),
        timestamp_ms: 1,
        step_index: 2,
    });
    implement_state.command_history.push_back(CommandExecution {
        command: "python3 -m unittest tests.test_path_utils -v".to_string(),
        exit_code: 0,
        stdout: "OK".to_string(),
        stderr: String::new(),
        timestamp_ms: 2,
        step_index: 5,
    });
    implement_state.tool_execution_log.insert(
        "evidence::workspace_edit_applied=true".to_string(),
        crate::agentic::runtime::types::ToolCallStatus::Executed(
            "step=4;tool=file__write;path=path_utils.py".to_string(),
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
    .expect("paused refusal with successful verification should merge");

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

    let materialized = load_worker_session_result(&state, implement_id)
        .expect("worker result lookup should succeed")
        .expect("worker result should exist");
    assert_eq!(materialized.status, "Completed");
    assert!(materialized.success);
    let raw_output = materialized
        .raw_output
        .as_deref()
        .expect("completed worker should synthesize raw output");
    assert!(
        raw_output.contains("Touched files: path_utils.py"),
        "{raw_output}"
    );
    assert!(
        raw_output.contains("Verification: python3 -m unittest tests.test_path_utils -v (passed)"),
        "{raw_output}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn citation_grounded_brief_surfaces_research_verifier_scorecard() {
    let (tx, mut rx) = tokio::sync::broadcast::channel(32);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic = "Research the latest kernel scheduler benchmark scorecards.";
    let mut parent_state = build_parent_state_with_goal(topic, 128);

    let research = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x73; 32],
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
            "Findings:\n- Linux 6.9 scheduler latency improved in recent tests.\nSources:\n- https://www.kernel.org/doc/html/latest/scheduler/index.html\n- https://lwn.net/Articles/123456/\n- https://benchmark.example.com/kernel-scheduler-2026-03-31\nFreshness note: checked on 2026-03-31."
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
    assert!(merged_research.contains("Playbook: Live Research Brief (live_research_brief)"));
    assert!(merged_research.contains("advanced to 'Verify grounding'"));

    let run_after_research =
        load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
            .expect("research playbook run lookup should succeed")
            .expect("research playbook run should exist");
    assert_eq!(
        run_after_research.steps[0].status,
        ParentPlaybookStepStatus::Completed
    );
    assert_eq!(
        run_after_research.steps[1].status,
        ParentPlaybookStepStatus::Running
    );
    assert_eq!(
        run_after_research.steps[1].workflow_id.as_deref(),
        Some("citation_audit")
    );
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
    assert!(verify_state.goal.contains("full_handoff"));
    assert!(verify_state.goal.contains("Sources:"));
    assert!(verify_state
        .goal
        .contains("https://www.kernel.org/doc/html/latest/scheduler/index.html"));
    verify_state.status = AgentStatus::Completed(Some(
            "- verdict: passed\n- freshness_status: passed\n- quote_grounding_status: needs_attention\n- notes: One benchmark metric still needs a direct quote read-back from the benchmark source."
                .to_string(),
        ));
    persist_agent_state(
        &mut state,
        &verify_key,
        &verify_state,
        service.memory_runtime.as_ref(),
    )
    .expect("verifier state update should persist");

    let merged_verify = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        4,
        0,
        &hex::encode(verify_id),
    )
    .await
    .expect("citation verifier merge should complete playbook");
    assert!(merged_verify.contains("Playbook: Citation Audit (citation_audit)"));
    assert!(merged_verify.contains("Parent playbook 'Citation-Grounded Brief' completed."));

    let final_run =
        load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
            .expect("final playbook run lookup should succeed")
            .expect("final playbook run should exist");
    assert_eq!(final_run.status, ParentPlaybookStatus::Completed);
    let parent_completion = match &parent_state.status {
        AgentStatus::Completed(Some(output)) => output,
        other => panic!("expected completed parent status, got {:?}", other),
    };
    assert!(parent_completion.contains("Linux 6.9 scheduler latency improved"));
    assert!(parent_completion.contains("Verification verdict"));
    assert!(parent_completion.contains("verdict: passed"));
    let scorecard = final_run.steps[1]
        .research_scorecard
        .as_ref()
        .expect("research verifier scorecard should be captured");
    assert_eq!(scorecard.verdict, "passed");
    assert_eq!(scorecard.source_count, 3);
    assert_eq!(scorecard.distinct_domain_count, 3);
    assert!(scorecard.source_count_floor_met);
    assert!(scorecard.source_independence_floor_met);
    assert_eq!(scorecard.freshness_status, "passed");
    assert_eq!(scorecard.quote_grounding_status, "needs_attention");
    assert!(scorecard
        .notes
        .as_deref()
        .is_some_and(|notes| notes.contains("direct quote read-back")));

    let mut saw_step_completed_scorecard = false;
    let mut saw_completed_scorecard = false;
    while let Ok(event) = rx.try_recv() {
        if let KernelEvent::WorkloadReceipt(receipt_event) = event {
            if let WorkloadReceipt::ParentPlaybook(receipt) = receipt_event.receipt {
                assert_eq!(receipt.planner_authority, "kernel");
                assert_eq!(receipt.verifier_role, "citation_verifier");
                match receipt.phase.as_str() {
                    "step_completed"
                        if receipt.workflow_id.as_deref() == Some("citation_audit") =>
                    {
                        let scorecard = receipt
                            .research_scorecard
                            .as_ref()
                            .expect("step-completed receipt should carry scorecard");
                        assert_eq!(scorecard.verdict, "passed");
                        assert_eq!(scorecard.source_count, 3);
                        assert_eq!(receipt.verifier_outcome, "pass");
                        saw_step_completed_scorecard = true;
                    }
                    "completed" => {
                        let scorecard = receipt
                            .research_scorecard
                            .as_ref()
                            .expect("completed receipt should carry scorecard");
                        assert_eq!(scorecard.quote_grounding_status, "needs_attention");
                        assert_eq!(receipt.verifier_outcome, "pass");
                        saw_completed_scorecard = true;
                    }
                    _ => {}
                }
            }
        }
    }

    assert!(
        saw_step_completed_scorecard,
        "step_completed receipt should carry the research scorecard"
    );
    assert!(
        saw_completed_scorecard,
        "completed receipt should preserve the research scorecard"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn citation_grounded_brief_merges_child_pending_search_inventory_into_parent() {
    let (tx, _rx) = tokio::sync::broadcast::channel(32);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic = "Research the latest NIST post-quantum cryptography standards.";
    let mut parent_state = build_parent_state_with_goal(topic, 128);
    parent_state.pending_search_completion = Some(PendingSearchCompletion {
        query: topic.to_string(),
        query_contract: "document_briefing".to_string(),
        url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
        started_step: 1,
        started_at_ms: 10,
        deadline_ms: 20,
        candidate_urls: vec!["https://csrc.nist.gov/pubs/ir/8413/final".to_string()],
        candidate_source_hints: vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/final".to_string(),
            title: Some("NIST IR 8413".to_string()),
            excerpt: "Status report for the PQC standardization process.".to_string(),
        }],
        attempted_urls: vec!["https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string()],
        blocked_urls: Vec::new(),
        successful_reads: vec![PendingSearchReadSummary {
            url: "https://csrc.nist.gov/pubs/ir/8413/upd1/final".to_string(),
            title: Some("NIST IR 8413 Update 1".to_string()),
            excerpt: "Official NIST status report for post-quantum cryptography.".to_string(),
        }],
        min_sources: 2,
        ..PendingSearchCompletion::default()
    });

    let research = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x75; 32],
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
    research_state.pending_search_completion = Some(PendingSearchCompletion {
            query: topic.to_string(),
            query_contract: "document_briefing".to_string(),
            url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
            started_step: 3,
            started_at_ms: 30,
            deadline_ms: 40,
            candidate_urls: vec![
                "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
            ],
            candidate_source_hints: vec![
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/203/final".to_string(),
                    title: Some("FIPS 203".to_string()),
                    excerpt: "Module-Lattice-Based Key-Encapsulation Mechanism Standard.".to_string(),
                },
                PendingSearchReadSummary {
                    url: "https://csrc.nist.gov/pubs/fips/204/final".to_string(),
                    title: Some("FIPS 204".to_string()),
                    excerpt: "Module-Lattice-Based Digital Signature Standard.".to_string(),
                },
            ],
            attempted_urls: vec![
                "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
            ],
            blocked_urls: Vec::new(),
            successful_reads: vec![PendingSearchReadSummary {
                url: "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization".to_string(),
                title: Some("Post-Quantum Cryptography Standardization".to_string()),
                excerpt: "FIPS 203, FIPS 204, and FIPS 205 are the initial finalized standards.".to_string(),
            }],
            min_sources: 2,
            ..PendingSearchCompletion::default()
        });
    research_state.status = AgentStatus::Completed(Some(
        "Briefing for NIST PQC standards with citations to IR 8413 and the PQC project page."
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

    let parent_pending = parent_state
        .pending_search_completion
        .as_ref()
        .expect("parent should inherit merged pending search inventory");
    assert_eq!(parent_pending.query, topic);
    assert!(
        parent_pending
            .successful_reads
            .iter()
            .any(|source| { source.url == "https://csrc.nist.gov/pubs/ir/8413/upd1/final" }),
        "parent should preserve existing official IR read"
    );
    assert!(
            parent_pending.successful_reads.iter().any(|source| {
                source.url
                    == "https://csrc.nist.gov/projects/post-quantum-cryptography/post-quantum-cryptography-standardization"
            }),
            "parent should inherit the child project-page read"
        );
    assert!(
        parent_pending
            .candidate_source_hints
            .iter()
            .any(|source| { source.url == "https://csrc.nist.gov/pubs/fips/203/final" }),
        "parent should inherit child follow-on authority hints"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn citation_grounded_brief_bootstrapped_verifier_completes_from_inherited_handoff() {
    let (tx, _rx) = tokio::sync::broadcast::channel(32);
    let (service, _temp_dir) = build_test_service(tx);
    let mut state = IAVLTree::new(HashCommitmentScheme::new());
    let topic = "Research the latest NIST post-quantum cryptography standards.";
    let mut parent_state = build_parent_state_with_goal(topic, 128);

    let research = spawn_delegated_child_session(
        &service,
        &mut state,
        &mut parent_state,
        [0x74; 32],
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
            "Briefing for 'Research the latest NIST post-quantum cryptography standards.' (as of 2026-04-01T05:16:29Z UTC)\n\nWhat happened:\n- NIST's NCCoE migration draft remains a current official source for PQC migration activity.\n\nKey evidence:\n- NCCoE published the draft migration practice guide and IBM summarized related NIST framework context.\n\nCitations:\n- Migration to Post-Quantum Cryptography Quantum Read-iness: Testing Draft Standards | https://www.nccoe.nist.gov/sites/default/files/2023-12/pqc-migration-nist-sp-1800-38c-preliminary-draft.pdf | 2026-04-01T05:16:29Z | retrieved_utc\n- IBM NIST cybersecurity framework summary | https://www.ibm.com/es-es/think/insights/nist-cybersecurity-framework-2 | 2026-04-01T05:16:29Z | retrieved_utc\n\nRun date (UTC): 2026-04-01\nRun timestamp (UTC): 2026-04-01T05:16:29Z\nOverall confidence: medium"
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
    let verify_state: AgentState =
        codec::from_bytes_canonical(&verify_bytes).expect("verifier state should decode");
    assert!(verify_state.execution_queue.is_empty());
    let verify_output = match &verify_state.status {
        AgentStatus::Completed(Some(output)) => output.as_str(),
        other => panic!("expected completed verifier bootstrap, got {:?}", other),
    };
    assert!(verify_output.contains("- verdict: passed"));
    assert!(verify_output.contains("- freshness_status: passed"));

    let merged_verify = await_child_worker_result(
        &service,
        &mut state,
        &mut parent_state,
        4,
        0,
        &hex::encode(verify_id),
    )
    .await
    .expect("bootstrapped verifier merge should complete playbook");
    assert!(!merged_verify.trim().is_empty());

    let final_run =
        load_parent_playbook_run(&state, parent_state.session_id, "citation_grounded_brief")
            .expect("final playbook run lookup should succeed")
            .expect("final playbook run should exist");
    let scorecard = final_run.steps[1]
        .research_scorecard
        .as_ref()
        .expect("research verifier scorecard should be captured");
    assert_eq!(scorecard.verdict, "passed");
    assert_eq!(scorecard.source_count, 2);
    assert_eq!(scorecard.distinct_domain_count, 2);
    assert_eq!(scorecard.freshness_status, "passed");
    assert_eq!(scorecard.quote_grounding_status, "passed");
    assert!(scorecard.source_count_floor_met);
    assert!(scorecard.source_independence_floor_met);
    let parent_completion = match &parent_state.status {
        AgentStatus::Completed(Some(output)) => output,
        other => panic!("expected completed parent status, got {:?}", other),
    };
    assert!(parent_completion.contains("Verification verdict"));
    assert!(parent_completion.contains("verdict: passed"));
}
