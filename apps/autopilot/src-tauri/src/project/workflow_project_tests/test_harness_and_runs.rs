#[test]
fn workflow_tests_validate_typed_targets_without_runtime_noise() {
    let root = temp_root("tests");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "basic-agent-answer".to_string(),
        name: Some("Validation Flow".to_string()),
    })
    .expect("workflow bundle should create");

    let result = run_workflow_tests(bundle.workflow_path.clone(), None)
        .expect("workflow test validation should run");
    assert_eq!(result.status, "passed");
    assert_eq!(result.passed, 1);
    assert_eq!(result.failed, 0);
    assert_eq!(result.blocked, 0);

    let broken_tests = vec![WorkflowTestCase {
        id: "missing-node".to_string(),
        name: "Missing node fails".to_string(),
        target_node_ids: vec!["node-that-does-not-exist".to_string()],
        target_subgraph_id: None,
        assertion: WorkflowTestAssertion {
            kind: "node_exists".to_string(),
            expected: None,
            expression: None,
        },
        status: None,
        last_message: None,
    }];
    save_workflow_tests(bundle.workflow_path.clone(), broken_tests).expect("tests should save");
    let result = run_workflow_tests(bundle.workflow_path, None)
        .expect("workflow test validation should run");
    assert_eq!(result.status, "failed");
    assert_eq!(result.failed, 1);
    assert!(result.results[0]
        .message
        .contains("node-that-does-not-exist"));
}

#[test]
fn workflow_tests_execute_schema_contains_and_custom_assertions() {
    let root = temp_root("executable-tests");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Executable Test Flow".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("blank workflow should create");

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![
        workflow_node(
            "scratch-source",
            "source",
            "Manual request",
            80,
            180,
            "Input",
            "manual",
        ),
        workflow_function_node(
            "scratch-function",
            "Scan repository",
            320,
            170,
            "return { summary: 'repo scan ok', count: 3, passed: true };",
        ),
        workflow_node(
            "scratch-output",
            "output",
            "Executable report",
            580,
            180,
            "Output",
            "report",
        ),
    ];
    if let Some(function_node) = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("scratch-function"))
    {
        logic_mut(function_node).insert(
            "functionBinding".to_string(),
            json!({
                "language": "javascript",
                "code": "return { summary: 'repo scan ok', count: 3, passed: true };",
                "outputSchema": {
                    "type": "object",
                    "required": ["summary", "count", "passed"],
                    "properties": {
                        "summary": { "type": "string" },
                        "count": { "type": "integer" },
                        "passed": { "type": "boolean" }
                    }
                },
                "sandboxPolicy": {
                    "timeoutMs": 1000,
                    "memoryMb": 64,
                    "outputLimitBytes": 4096,
                    "permissions": []
                },
                "testInput": {}
            }),
        );
    }
    workflow.edges = vec![
        workflow_edge(
            "edge-scratch-source-function",
            "scratch-source",
            "scratch-function",
        ),
        workflow_edge(
            "edge-scratch-function-output",
            "scratch-function",
            "scratch-output",
        ),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");
    save_workflow_tests(
        bundle.workflow_path.clone(),
        vec![
            WorkflowTestCase {
                id: "schema".to_string(),
                name: "Function output schema".to_string(),
                target_node_ids: vec!["scratch-function".to_string()],
                target_subgraph_id: None,
                assertion: WorkflowTestAssertion {
                    kind: "schema_matches".to_string(),
                    expected: Some(json!({
                        "type": "object",
                        "required": ["summary", "count", "passed"],
                        "properties": {
                            "summary": { "type": "string" },
                            "count": { "type": "integer" },
                            "passed": { "type": "boolean" }
                        }
                    })),
                    expression: None,
                },
                status: None,
                last_message: None,
            },
            WorkflowTestCase {
                id: "contains".to_string(),
                name: "Function mentions scan".to_string(),
                target_node_ids: vec!["scratch-function".to_string()],
                target_subgraph_id: None,
                assertion: WorkflowTestAssertion {
                    kind: "output_contains".to_string(),
                    expected: Some(json!("repo scan ok")),
                    expression: None,
                },
                status: None,
                last_message: None,
            },
            WorkflowTestCase {
                id: "custom".to_string(),
                name: "Function count is stable".to_string(),
                target_node_ids: vec!["scratch-function".to_string()],
                target_subgraph_id: None,
                assertion: WorkflowTestAssertion {
                    kind: "custom".to_string(),
                    expected: Some(json!(3)),
                    expression: Some(
                        "return input.value.result.count === input.expected;".to_string(),
                    ),
                },
                status: None,
                last_message: None,
            },
        ],
    )
    .expect("tests should save");

    let result = run_workflow_tests(bundle.workflow_path.clone(), None).expect("tests should run");
    assert_eq!(result.status, "passed");
    assert_eq!(result.passed, 3);
    assert!(list_workflow_runs(bundle.workflow_path)
        .expect("test-backed run should record")
        .iter()
        .any(|run| run.status == "passed"));
}

#[test]
fn workflow_tests_can_pass_target_outputs_before_downstream_interrupt() {
    let root = temp_root("tests-before-interrupt");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Interrupted Testable Flow".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("blank workflow should create");

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![
        workflow_node(
            "scratch-source",
            "source",
            "Manual request",
            80,
            180,
            "Input",
            "manual",
        ),
        workflow_function_node(
            "scratch-function",
            "Scan repository",
            320,
            170,
            "return { summary: 'repo scan ok', count: 3, passed: true };",
        ),
        workflow_node(
            "scratch-model",
            "model_call",
            "Diagnose gaps",
            580,
            180,
            "Model",
            "reasoning",
        ),
        workflow_node(
            "scratch-gate",
            "human_gate",
            "Approve write",
            840,
            180,
            "Gate",
            "approval",
        ),
        workflow_node(
            "scratch-output",
            "output",
            "Report",
            1100,
            180,
            "Output",
            "report",
        ),
    ];
    workflow.edges = vec![
        workflow_edge(
            "edge-scratch-source-function",
            "scratch-source",
            "scratch-function",
        ),
        workflow_edge(
            "edge-scratch-function-model",
            "scratch-function",
            "scratch-model",
        ),
        workflow_edge("edge-scratch-model-gate", "scratch-model", "scratch-gate"),
        workflow_edge("edge-scratch-gate-output", "scratch-gate", "scratch-output"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");
    save_workflow_tests(
        bundle.workflow_path.clone(),
        vec![
            WorkflowTestCase {
                id: "function-schema".to_string(),
                name: "Function output schema".to_string(),
                target_node_ids: vec!["scratch-function".to_string()],
                target_subgraph_id: None,
                assertion: WorkflowTestAssertion {
                    kind: "schema_matches".to_string(),
                    expected: Some(json!({
                        "type": "object",
                        "required": ["summary", "count", "passed"],
                        "properties": {
                            "summary": { "type": "string" },
                            "count": { "type": "integer" },
                            "passed": { "type": "boolean" }
                        }
                    })),
                    expression: None,
                },
                status: None,
                last_message: None,
            },
            WorkflowTestCase {
                id: "model-completed".to_string(),
                name: "Model produced diagnosis".to_string(),
                target_node_ids: vec!["scratch-model".to_string()],
                target_subgraph_id: None,
                assertion: WorkflowTestAssertion {
                    kind: "output_contains".to_string(),
                    expected: Some(json!("completed")),
                    expression: None,
                },
                status: None,
                last_message: None,
            },
        ],
    )
    .expect("tests should save");

    let result = run_workflow_tests(bundle.workflow_path.clone(), None).expect("tests should run");
    assert_eq!(result.status, "passed");
    assert_eq!(result.passed, 2);
    assert!(list_workflow_runs(bundle.workflow_path)
        .expect("test-backed run should record")
        .iter()
        .any(|run| run.status == "interrupted"));
}

#[test]
fn workflow_test_assertion_node_evaluates_configured_condition() {
    let root = temp_root("test-assertion-node");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Runtime Assertion Node".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("blank workflow should create");

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![
        workflow_node(
            "assert-source",
            "source",
            "Assertion input",
            80,
            180,
            "Input",
            "manual",
        ),
        workflow_node(
            "assert-node",
            "test_assertion",
            "Must mention approved",
            320,
            170,
            "Assert",
            "contains",
        ),
        workflow_node(
            "assert-output",
            "output",
            "Assertion output",
            580,
            180,
            "Output",
            "report",
        ),
    ];
    if let Some(source_node) = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("assert-source"))
    {
        logic_mut(source_node).insert("payload".to_string(), json!({"text": "draft only"}));
    }
    if let Some(assertion_node) = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("assert-node"))
    {
        logic_mut(assertion_node).insert("assertionKind".to_string(), json!("output_contains"));
        logic_mut(assertion_node).insert("expected".to_string(), json!("approved"));
    }
    workflow.edges = vec![
        workflow_edge("edge-source-assert", "assert-source", "assert-node"),
        workflow_edge("edge-assert-output", "assert-node", "assert-output"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run = run_workflow_project(bundle.workflow_path, None).expect("run should execute");
    assert_eq!(run.summary.status, "failed");
    assert!(run
        .node_runs
        .iter()
        .any(|node_run| node_run.node_id == "assert-node" && node_run.status == "error"));
}

#[test]
fn workflow_templates_round_trip_agent_examples() {
    let root = temp_root("templates");
    let template_ids = [
        "basic-agent-answer",
        "repo-function-test",
        "adapter-connector-check",
        "plugin-tool-action",
        "human-gated-change",
        "jpg-to-svg-tracing",
        "proposal-mutation",
        "software-request-triage-agent",
        "product-feedback-router-agent",
        "weekly-metrics-reporting-agent",
        "month-end-accounting-close-agent",
        "slack-qa-agent",
        "heavy-repo-test-engineer",
        "heavy-mcp-research-operator",
        "heavy-connector-triage",
        "heavy-financial-close",
        "heavy-media-transform",
        "heavy-scheduled-reporter",
        "heavy-self-improving-proposal",
    ];

    for template_id in template_ids {
        let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
            project_root: root.display().to_string(),
            template_id: template_id.to_string(),
            name: None,
        })
        .expect("template should instantiate");
        assert!(PathBuf::from(&bundle.workflow_path).exists());
        assert!(!bundle.workflow.nodes.is_empty());
        assert!(!bundle.tests.is_empty());
        assert_eq!(
            bundle
                .workflow
                .nodes
                .iter()
                .any(|node| node.get("type").and_then(Value::as_str) == Some("model")),
            false
        );
    }
}

#[test]
fn workflow_run_validation_proposal_and_evidence_are_sidecars() {
    let root = temp_root("runs");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "basic-agent-answer".to_string(),
        name: Some("Runnable Agent".to_string()),
    })
    .expect("template should instantiate");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");

    let run = run_workflow_project(bundle.workflow_path.clone(), None)
        .expect("workflow run should record");
    assert_eq!(run.summary.status, "passed");
    assert!(!run.checkpoints.is_empty());
    assert!(!run.events.is_empty());
    assert!(run
        .node_runs
        .iter()
        .any(|node_run| node_run.input.is_some() && node_run.output.is_some()));

    let runs = list_workflow_runs(bundle.workflow_path.clone()).expect("runs should list");
    assert_eq!(runs.len(), 1);
    assert!(workflow_runs_path(&PathBuf::from(&bundle.workflow_path)).is_dir());
    assert!(
        workflow_run_result_path(&PathBuf::from(&bundle.workflow_path), &run.summary.id).exists()
    );

    let proposal_bundle = create_workflow_proposal(
        bundle.workflow_path.clone(),
        CreateWorkflowProposalRequest {
            title: "Bounded edit".to_string(),
            summary: "Review a bounded workflow edit.".to_string(),
            bounded_targets: vec!["model-answer".to_string()],
            workflow_patch: Some(bundle.workflow.clone()),
            code_diff: Some("workflow graph only".to_string()),
        },
    )
    .expect("proposal should create");
    assert_eq!(proposal_bundle.proposals.len(), 1);

    let evidence = list_workflow_evidence(bundle.workflow_path).expect("evidence should list");
    assert!(evidence.iter().any(|entry| entry.kind == "run"));
    assert!(evidence.iter().any(|entry| entry.kind == "proposal"));
}

#[test]
fn workflow_proposal_apply_enforces_bounded_node_targets() {
    let root = temp_root("proposal-bounds");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "basic-agent-answer".to_string(),
        name: Some("Bounded Proposal".to_string()),
    })
    .expect("template should instantiate");
    let node_ids = bundle
        .workflow
        .nodes
        .iter()
        .filter_map(workflow_node_id)
        .collect::<Vec<_>>();
    assert!(node_ids.len() >= 2);
    let allowed_bound = node_ids[0].clone();
    let changed_node_id = node_ids[1].clone();
    let mut patch = bundle.workflow.clone();
    let changed_node = patch
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some(changed_node_id.as_str()))
        .expect("changed node should exist");
    logic_mut(changed_node).insert(
        "prompt".to_string(),
        json!("Updated by bounded proposal test."),
    );

    let blocked_bundle = create_workflow_proposal(
        bundle.workflow_path.clone(),
        CreateWorkflowProposalRequest {
            title: "Unsafe patch".to_string(),
            summary: "Patch changes a node outside the declared proposal bounds.".to_string(),
            bounded_targets: vec![allowed_bound],
            workflow_patch: Some(patch.clone()),
            code_diff: None,
        },
    )
    .expect("proposal should create");
    let blocked_proposal = blocked_bundle
        .proposals
        .iter()
        .find(|proposal| proposal.title == "Unsafe patch")
        .expect("blocked proposal should be present");
    assert!(blocked_proposal
        .config_diff
        .as_ref()
        .expect("config diff should exist")
        .changed_node_ids
        .contains(&changed_node_id));
    assert!(
        blocked_proposal
            .sidecar_diff
            .as_ref()
            .expect("sidecar diff should exist")
            .proposals_changed
    );
    let error = apply_workflow_proposal(bundle.workflow_path.clone(), blocked_proposal.id.clone())
        .expect_err("out-of-bounds proposal should not apply");
    assert!(error.contains("exceeds declared bounds"));
    assert!(error.contains(&changed_node_id));

    let allowed_bundle = create_workflow_proposal(
        bundle.workflow_path.clone(),
        CreateWorkflowProposalRequest {
            title: "Safe patch".to_string(),
            summary: "Patch changes only the declared node bound.".to_string(),
            bounded_targets: vec![changed_node_id.clone()],
            workflow_patch: Some(patch),
            code_diff: None,
        },
    )
    .expect("proposal should create");
    let allowed_proposal_id = allowed_bundle
        .proposals
        .iter()
        .find(|proposal| proposal.title == "Safe patch")
        .expect("allowed proposal should be present")
        .id
        .clone();
    let applied = apply_workflow_proposal(bundle.workflow_path.clone(), allowed_proposal_id)
        .expect("in-bounds proposal should apply");
    let applied_node = applied
        .workflow
        .nodes
        .iter()
        .find(|node| workflow_node_id(node).as_deref() == Some(changed_node_id.as_str()))
        .expect("applied node should exist");
    assert_eq!(
        applied_node
            .get("config")
            .and_then(|config| config.get("logic"))
            .and_then(|logic| logic.get("prompt"))
            .and_then(Value::as_str),
        Some("Updated by bounded proposal test.")
    );
}

#[test]
fn workflow_run_interrupt_resume_and_checkpoint_fork_are_durable() {
    let root = temp_root("interrupt");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "human-gated-change".to_string(),
        name: Some("Human Gated Change".to_string()),
    })
    .expect("template should instantiate");

    let interrupted = run_workflow_project(bundle.workflow_path.clone(), None)
        .expect("workflow run should pause");
    assert_eq!(interrupted.summary.status, "interrupted");
    assert!(interrupted.interrupt.is_some());
    let thread_id = interrupted.thread.id.clone();
    let checkpoints = list_workflow_checkpoints(bundle.workflow_path.clone(), thread_id.clone())
        .expect("checkpoints should list");
    assert!(!checkpoints.is_empty());

    let fork = fork_workflow_checkpoint(
        bundle.workflow_path.clone(),
        WorkflowCheckpointForkRequest {
            checkpoint_id: checkpoints[0].id.clone(),
            name: Some("Review fork".to_string()),
            input: None,
        },
    )
    .expect("checkpoint should fork");
    assert_ne!(fork.id, thread_id);

    let resumed = resume_workflow_run(
        bundle.workflow_path.clone(),
        WorkflowResumeRequest {
            run_id: Some(interrupted.summary.id.clone()),
            thread_id,
            node_id: None,
            interrupt_id: interrupted.interrupt.as_ref().map(|item| item.id.clone()),
            checkpoint_id: interrupted.thread.latest_checkpoint_id.clone(),
            outcome: "approve".to_string(),
            edited_state: None,
        },
    )
    .expect("workflow should resume");
    assert_eq!(resumed.summary.status, "passed");
    assert!(resumed
        .node_runs
        .iter()
        .any(|run| run.node_type == "human_gate" && run.status == "success"));
    let comparison = compare_workflow_runs(
        bundle.workflow_path,
        interrupted.summary.id,
        resumed.summary.id,
    )
    .expect("runs should compare");
    assert!(comparison.status_changed);
    assert!(comparison
        .node_changes
        .iter()
        .any(|change| change.node_id == "gate-approval" && change.output_changed));
    assert!(comparison
        .state_changes
        .iter()
        .any(|change| change.key == "gate-approval"));
}

#[test]
fn workflow_failed_function_resumes_from_repaired_checkpoint() {
    let root = temp_root("failed-resume");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Failed Function Resume".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");
    let mut workflow = bundle.workflow.clone();
    let source = workflow_node(
        "resume-source",
        "source",
        "Resume source",
        120,
        160,
        "Source",
        "payload",
    );
    let mut function = workflow_node(
        "resume-function",
        "function",
        "Repairable function",
        360,
        160,
        "Function",
        "sandbox",
    );
    logic_mut(&mut function).insert("fail".to_string(), json!(true));
    let output = workflow_node(
        "resume-output",
        "output",
        "Resume output",
        600,
        160,
        "Output",
        "markdown",
    );
    workflow.nodes = vec![source, function, output];
    workflow.edges = vec![
        workflow_edge("edge-source-function", "resume-source", "resume-function"),
        workflow_edge("edge-function-output", "resume-function", "resume-output"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow.clone())
        .expect("workflow should save");

    let failed =
        run_workflow_project(bundle.workflow_path.clone(), None).expect("run should execute");
    assert_eq!(failed.summary.status, "failed");
    assert!(failed
        .node_runs
        .iter()
        .any(|run| run.node_id == "resume-function" && run.status == "error"));
    let failed_run_path =
        workflow_run_result_path(&PathBuf::from(&bundle.workflow_path), &failed.summary.id);
    assert!(failed_run_path.exists());

    let repaired_function = workflow
        .nodes
        .iter_mut()
        .find(|node| node.get("id").and_then(Value::as_str) == Some("resume-function"))
        .expect("function node should exist");
    logic_mut(repaired_function).remove("fail");
    logic_mut(repaired_function).insert(
        "code".to_string(),
        json!("return { repaired: true, source: input };"),
    );
    logic_mut(repaired_function).insert(
        "functionBinding".to_string(),
        json!({
            "language": "javascript",
            "code": "return { repaired: true, source: input };",
            "outputSchema": {
                "type": "object",
                "required": ["repaired"],
                "properties": {
                    "repaired": { "type": "boolean" }
                }
            },
            "sandboxPolicy": {
                "timeoutMs": 1000,
                "memoryMb": 64,
                "outputLimitBytes": 32768,
                "permissions": []
            },
            "testInput": { "payload": "resume" }
        }),
    );
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("repair should save");

    let resumed = resume_workflow_run(
        bundle.workflow_path.clone(),
        WorkflowResumeRequest {
            run_id: Some(failed.summary.id.clone()),
            thread_id: failed.thread.id.clone(),
            node_id: Some("resume-function".to_string()),
            interrupt_id: None,
            checkpoint_id: failed.thread.latest_checkpoint_id.clone(),
            outcome: "repair".to_string(),
            edited_state: None,
        },
    )
    .expect("failed node should resume after repair");
    assert_eq!(resumed.summary.status, "passed");
    assert_ne!(resumed.summary.id, failed.summary.id);
    assert!(resumed
        .node_runs
        .iter()
        .any(|run| run.node_id == "resume-function" && run.status == "success"));
    assert!(resumed
        .node_runs
        .iter()
        .any(|run| run.node_id == "resume-output" && run.status == "success"));
    assert!(
        failed_run_path.exists(),
        "failed attempt sidecar remains durable"
    );
}

#[test]
fn workflow_validation_blocks_unbound_runtime_nodes_without_name_heuristics() {
    let root = temp_root("validation");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "basic-agent-answer".to_string(),
        name: Some("Typed Blockers".to_string()),
    })
    .expect("workflow bundle should create");

    let mut workflow = bundle.workflow.clone();
    if let Some(model_node) = workflow
        .nodes
        .iter_mut()
        .find(|node| node.get("type").and_then(Value::as_str) == Some("model_call"))
    {
        if let Some(logic) = model_node
            .get_mut("config")
            .and_then(|config| config.get_mut("logic"))
        {
            logic
                .as_object_mut()
                .expect("logic object")
                .remove("modelRef");
        }
    }
    write_json_pretty(&PathBuf::from(&bundle.workflow_path), &workflow)
        .expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "blocked");
    assert!(validation
        .missing_config
        .iter()
        .any(|issue| issue.code == "missing_model_binding"));
    let run = run_workflow_project(bundle.workflow_path, None).expect("run should block");
    assert_eq!(run.summary.status, "blocked");
    assert!(run.node_runs.is_empty());
    assert!(run
        .completion_requirements
        .iter()
        .any(|requirement| requirement.status == "missing"));
}

