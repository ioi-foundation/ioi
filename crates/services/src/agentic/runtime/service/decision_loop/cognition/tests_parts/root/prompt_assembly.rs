#[test]
fn prompt_assembly_enforces_section_budgets_and_reports_truncation() {
    let assembly = assemble_prompt_sections(vec![
        PromptSection::new("alpha", "abcdef").with_budget(4),
        PromptSection::new("beta", "second section"),
        PromptSection::new("empty", "   ").with_budget(10),
    ]);

    assert!(assembly.system_instructions.contains("a..."));
    assert!(assembly.system_instructions.contains("second section"));
    assert!(!assembly.system_instructions.contains("empty"));
    assert_eq!(
        assembly.report.total_chars,
        assembly.system_instructions.chars().count()
    );
    assert_eq!(assembly.report.sections.len(), 3);
    assert!(assembly.report.sections[0].truncated);
    assert!(!assembly.report.sections[1].truncated);
    assert!(!assembly.report.sections[2].included);

    let report = format_prompt_assembly_report(&assembly.report);
    assert!(report.contains("alpha:included=true"));
    assert!(report.contains("truncated=true"));
    assert!(report.contains("empty:included=false"));
}

#[test]
fn standard_prompt_assembly_omits_empty_sections_and_keeps_specialized_sections() {
    let assembly = build_standard_prompt_assembly(
        "Kernel guidance.",
        "Chromium",
        "Finish checkout",
        "browser.checkout (scope=Browser band=High score=0.99)",
        "CORE MEMORY:\n- Current Goal: Finish checkout",
        "",
        "",
        "Strategy goes here.",
        "TOOL ROUTING CONTRACT:\n- prefer specific tools",
        "",
        "",
        "COMMAND EXECUTION CONTRACT:\n- Use terminal evidence.",
        "WORKSPACE CHANGE LIFECYCLE CONTRACT:\n- Roll back before reading.",
        "browser__inspect",
        "CURRENT BROWSER OBSERVATION:\n<button id=\"checkout\" />",
        "",
        "",
        "PENDING WEB TOOL EVIDENCE:\nTyped market quote evidence from tool results:\n- Akash Network: price $0.78. Market cap: $230M.",
        "RECENT SESSION EVENTS:\nclicked checkout",
        "",
        "WORKSPACE CONTEXT:\nrepo=ioi",
        "WORKSPACE CHANGE HANDLES:\n- change_id=workspace_change:123 lifecycle=applied tool=file__edit path=src/lib.rs edits=1 rollback_available=true",
        "OPERATING RULES:\n- verify success",
        Some("MAILBOX CONNECTOR RULE:\n- stay mailbox-local"),
        Some("SELECTED EXECUTION ROUTE:\n- Parent playbook: `evidence_audited_patch`"),
        Some("ACTIVE WORKER CONTRACT:\n- Finish with a bounded brief"),
        "WORKSPACE OPS CONTRACT:\n- prefer filesystem tools",
        "",
    );

    assert!(assembly
        .system_instructions
        .contains("=== LAYER 1: KERNEL POLICY ==="));
    assert!(assembly
        .system_instructions
        .contains("CURRENT BROWSER OBSERVATION"));
    assert!(assembly
        .system_instructions
        .contains("RECENT SESSION EVENTS"));
    assert!(assembly
        .system_instructions
        .contains("PENDING WEB TOOL EVIDENCE"));
    assert!(assembly
        .system_instructions
        .contains("WORKSPACE CHANGE LIFECYCLE CONTRACT"));
    assert!(assembly
        .system_instructions
        .contains("MAILBOX CONNECTOR RULE"));
    assert!(assembly
        .system_instructions
        .contains("SELECTED EXECUTION ROUTE"));
    assert!(assembly
        .system_instructions
        .contains("ACTIVE WORKER CONTRACT"));
    assert!(assembly
        .system_instructions
        .contains("WORKSPACE OPS CONTRACT"));
    assert!(assembly
        .system_instructions
        .contains("WORKSPACE CHANGE HANDLES"));
    assert!(assembly
        .system_instructions
        .contains("TOOL ROUTING CONTRACT"));
    assert!(!assembly.system_instructions.contains("automation.monitor"));

    let included_sections: Vec<_> = assembly
        .report
        .sections
        .iter()
        .filter(|section| section.included)
        .map(|section| section.name)
        .collect();
    assert!(included_sections.contains(&"mailbox_instruction"));
    assert!(included_sections.contains(&"selected_parent_playbook_instruction"));
    assert!(included_sections.contains(&"active_worker_instruction"));
    assert!(included_sections.contains(&"workspace_scope_contract"));
    assert!(included_sections.contains(&"workspace_change_context"));
    assert!(included_sections.contains(&"tool_routing_contract"));
    assert!(!included_sections.contains(&"automation_monitor_contract"));
}

#[test]
fn selected_parent_playbook_instruction_surfaces_root_route_kickoff() {
    let rendered = render_selected_parent_playbook_instruction(Some(&ResolvedIntentState {
        intent_id: "workspace.ops".to_string(),
        scope: IntentScopeProfile::WorkspaceOps,
        band: ioi_types::app::agentic::IntentConfidenceBand::High,
        score: 0.98,
        top_k: vec![],
        required_capabilities: vec![],
        required_evidence: vec![],
        success_conditions: vec![],
        risk_class: "medium".to_string(),
        preferred_tier: "tool_first".to_string(),
        intent_catalog_version: "test".to_string(),
        embedding_model_id: "test".to_string(),
        embedding_model_version: "test".to_string(),
        similarity_function_id: "test".to_string(),
        intent_set_hash: [0u8; 32],
        tool_registry_hash: [0u8; 32],
        capability_ontology_hash: [0u8; 32],
        query_normalization_version: "test".to_string(),
        intent_catalog_source_hash: [0u8; 32],
        evidence_requirements_hash: [0u8; 32],
        provider_selection: None,
        instruction_contract: Some(ioi_types::app::agentic::InstructionContract {
            operation: "delegate".to_string(),
            side_effect_mode: ioi_types::app::agentic::InstructionSideEffectMode::Update,
            slot_bindings: vec![
                ioi_types::app::agentic::InstructionSlotBinding {
                    slot: "playbook_id".to_string(),
                    binding_kind: ioi_types::app::agentic::InstructionBindingKind::UserLiteral,
                    value: Some("evidence_audited_patch".to_string()),
                    origin: ioi_types::app::agentic::ArgumentOrigin::ModelInferred,
                    protected_slot_kind: ioi_types::app::agentic::ProtectedSlotKind::Unknown,
                },
                ioi_types::app::agentic::InstructionSlotBinding {
                    slot: "template_id".to_string(),
                    binding_kind: ioi_types::app::agentic::InstructionBindingKind::UserLiteral,
                    value: Some("context_worker".to_string()),
                    origin: ioi_types::app::agentic::ArgumentOrigin::ModelInferred,
                    protected_slot_kind: ioi_types::app::agentic::ProtectedSlotKind::Unknown,
                },
                ioi_types::app::agentic::InstructionSlotBinding {
                    slot: "workflow_id".to_string(),
                    binding_kind: ioi_types::app::agentic::InstructionBindingKind::UserLiteral,
                    value: Some("repo_context_brief".to_string()),
                    origin: ioi_types::app::agentic::ArgumentOrigin::ModelInferred,
                    protected_slot_kind: ioi_types::app::agentic::ProtectedSlotKind::Unknown,
                },
            ],
            negative_constraints: vec![],
            success_criteria: vec![],
        }),
        constrained: false,
    }))
    .expect("selected route guidance should render");

    assert!(rendered.contains("Root-session kickoff must be `agent__delegate`"));
    assert!(rendered.contains("evidence_audited_patch"));
    assert!(rendered.contains("planner_authority=kernel"));
    assert!(rendered.contains("verifier_role=test_verifier"));
    assert!(rendered.contains("context_worker"));
    assert!(rendered.contains("repo_context_brief"));
}

#[test]
fn active_worker_instruction_surfaces_repo_context_completion_contract() {
    let rendered = render_active_worker_instruction(
        Some(&WorkerAssignment {
            step_key: "delegate:test".to_string(),
            budget: 48,
            goal: "Inspect repo context".to_string(),
            success_criteria: "Return a bounded brief.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: None,
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("context_worker".to_string()),
            workflow_id: Some("repo_context_brief".to_string()),
            role: Some("Context Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__search".to_string(),
                "file__info".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded repo brief.".to_string(),
                expected_output: "Repo context brief.".to_string(),
                merge_mode: WorkerMergeMode::AppendAsEvidence,
                verification_hint: None,
            },
        }),
        "/tmp/repo",
    )
    .expect("worker instruction should render");

    assert!(rendered.contains("ACTIVE WORKER CONTRACT"));
    assert!(rendered.contains("evidence_audited_patch"));
    assert!(rendered.contains("repo_context_brief"));
    assert!(rendered.contains("Current working directory: `/tmp/repo`"));
    assert!(rendered.contains("Delegated goal: `Inspect repo context`"));
    assert!(rendered.contains("do not repeat the same root `file__info`"));
    assert!(rendered.contains("`likely_files`"));
}

#[test]
fn active_worker_instruction_surfaces_coder_repo_root_contract() {
    let rendered = render_active_worker_instruction(
        Some(&WorkerAssignment {
            step_key: "delegate:test".to_string(),
            budget: 96,
            goal: "Patch the workspace".to_string(),
            success_criteria: "Land the patch.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: None,
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        }),
        "/tmp/repo-root",
    )
    .expect("coder worker instruction should render");

    assert!(rendered.contains("patch_build_verify"));
    assert!(rendered.contains("Current working directory: `/tmp/repo-root`"));
    assert!(rendered.contains("Delegated goal: `Patch the workspace`"));
    assert!(rendered.contains("Do not spend more than one probe confirming the repo root"));
    assert!(rendered.contains("focused verification command"));
    assert!(rendered.contains("your next action must be `file__edit`"));
}

#[test]
fn active_worker_instruction_surfaces_patch_context_hints() {
    let rendered = render_active_worker_instruction(
        Some(&WorkerAssignment {
            step_key: "delegate:test".to_string(),
            budget: 96,
            goal: "Implement the parity fix.\n\n[PARENT PLAYBOOK CONTEXT]\n- likely_files: path_utils.py; tests/test_path_utils.py\n- targeted_checks: python3 -m unittest tests.test_path_utils -v\n- open_questions: Widen only if the focused verification command fails.".to_string(),
            success_criteria: "Land the patch.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: None,
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__search".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        }),
        "/tmp/repo-root",
    )
    .expect("coder worker instruction should render");

    assert!(rendered.contains("Likely patch files from parent context"));
    assert!(rendered.contains("path_utils.py, tests/test_path_utils.py"));
    assert!(rendered.contains("Focused verification command from parent context"));
    assert!(rendered.contains("python3 -m unittest tests.test_path_utils -v"));
    assert!(rendered.contains("do not reread the identical file"));
    assert!(rendered.contains("file__write"));
    assert!(!rendered.contains("file__replace_line"));
    assert!(rendered.contains("If `file__search` fails or returns nothing useful"));
}

#[test]
fn workspace_ops_contract_distinguishes_root_planner_from_active_worker() {
    let root_contract = render_workspace_scope_instruction(
        Some("evidence_audited_patch"),
        true,
        true,
        true,
        true,
        None,
    );
    let worker_contract = render_workspace_scope_instruction(
        Some("evidence_audited_patch"),
        true,
        true,
        true,
        true,
        Some(&WorkerAssignment {
            step_key: "delegate:test".to_string(),
            budget: 96,
            goal: "Patch the workspace".to_string(),
            success_criteria: "Land the patch.".to_string(),
            max_retries: 1,
            retries_used: 0,
            assigned_session_id: None,
            status: "running".to_string(),
            playbook_id: Some("evidence_audited_patch".to_string()),
            template_id: Some("coder".to_string()),
            workflow_id: Some("patch_build_verify".to_string()),
            role: Some("Coding Worker".to_string()),
            allowed_tools: vec![
                "file__read".to_string(),
                "file__edit".to_string(),
                "shell__start".to_string(),
                "agent__complete".to_string(),
            ],
            completion_contract: WorkerCompletionContract {
                success_criteria: "Return a bounded implementation handoff.".to_string(),
                expected_output: "Patch/build/test handoff.".to_string(),
                merge_mode: WorkerMergeMode::AppendSummaryToParent,
                verification_hint: None,
            },
        }),
    );

    assert!(root_contract.contains("Start the selected parent playbook with `agent__delegate`"));
    assert!(worker_contract.contains("do not restart the parent playbook from this worker"));
    assert!(worker_contract.contains("repeated repo-root `file__info` / `file__list` probes"));
}

#[test]
fn compact_browser_prompt_assembly_reports_named_sections() {
    let assembly = build_compact_browser_action_prompt_assembly(
        "Kernel guidance.",
        "Chromium",
        "Keep following the moving target.",
        "browser.hover (scope=Browser band=High score=0.91)",
        "CORE MEMORY:\n- Workflow Stage: Follow target",
        "URGENT UPDATE: keep the cursor on the shape.",
        "",
        "Choose a grounded next tool call.",
        "TOOL ROUTING CONTRACT:\n- prefer grounded browser tools",
        "",
        "browser__move_pointer",
        "CURRENT BROWSER OBSERVATION:\n<canvas id=\"surface\" />",
        "",
        "",
        "OPERATING RULES:\n- use grounded browser state",
    );

    assert!(assembly
        .system_instructions
        .contains("Follow policy. Output exactly one grounded browser tool call"));
    assert!(assembly
        .system_instructions
        .contains("TOOL ROUTING CONTRACT"));
    assert!(assembly
        .report
        .sections
        .iter()
        .any(|section| section.name == "state"));
    assert!(assembly
        .report
        .sections
        .iter()
        .any(|section| section.name == "available_tools" && section.included));
    assert!(assembly
        .report
        .sections
        .iter()
        .any(|section| section.name == "tool_routing_contract" && section.included));
}
