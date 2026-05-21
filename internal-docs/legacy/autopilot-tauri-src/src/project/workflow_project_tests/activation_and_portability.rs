#[test]
fn workflow_activation_readiness_blocks_operational_gaps() {
    let root = temp_root("activation-readiness");
    let blank = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Blank Activation".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("blank workflow should create");
    let readiness =
        validate_workflow_execution_readiness(blank.workflow_path).expect("readiness should run");
    assert_eq!(readiness.status, "blocked");
    assert!(readiness
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "missing_start_node"));
    assert!(readiness
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "missing_output_node"));
    assert!(readiness
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "missing_unit_tests"));

    let basic = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "basic-agent-answer".to_string(),
        name: Some("Model Activation".to_string()),
    })
    .expect("template workflow should instantiate");
    let basic_readiness =
        validate_workflow_execution_readiness(basic.workflow_path).expect("readiness should run");
    assert_eq!(basic_readiness.status, "blocked");
    assert!(basic_readiness
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "unbound_model_ref"));

    let attached = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Attached Model Activation".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("attached workflow should create");
    let mut workflow = attached.workflow.clone();
    workflow.nodes = vec![
        workflow_node(
            "attached-source",
            "source",
            "Input",
            120,
            180,
            "Input",
            "manual",
        ),
        workflow_node(
            "attached-model-binding",
            "model_binding",
            "Reasoning model binding",
            320,
            80,
            "Binding",
            "reasoning",
        ),
        workflow_node(
            "attached-model",
            "model_call",
            "Reason over input",
            520,
            180,
            "Model",
            "reasoning",
        ),
        workflow_node(
            "attached-output",
            "output",
            "Output",
            760,
            180,
            "Output",
            "summary",
        ),
    ];
    workflow.edges = vec![
        workflow_edge(
            "edge-attached-source-model",
            "attached-source",
            "attached-model",
        ),
        json!({
            "id": "edge-attached-model-binding",
            "from": "attached-model-binding",
            "to": "attached-model",
            "fromPort": "model",
            "toPort": "model",
            "type": "model",
            "connectionClass": "model",
            "data": { "connectionClass": "model" }
        }),
        workflow_edge(
            "edge-attached-model-output",
            "attached-model",
            "attached-output",
        ),
    ];
    save_workflow_project(attached.workflow_path.clone(), workflow)
        .expect("attached workflow should save");
    save_workflow_tests(
        attached.workflow_path.clone(),
        vec![WorkflowTestCase {
            id: "test-attached-model".to_string(),
            name: "Attached model exists".to_string(),
            target_node_ids: vec!["attached-model".to_string()],
            target_subgraph_id: None,
            assertion: WorkflowTestAssertion {
                kind: "node_exists".to_string(),
                expected: None,
                expression: None,
            },
            status: Some("idle".to_string()),
            last_message: None,
        }],
    )
    .expect("attached tests should save");
    let attached_readiness = validate_workflow_execution_readiness(attached.workflow_path.clone())
        .expect("attached readiness should run");
    assert!(!attached_readiness
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "unbound_model_ref"));
    assert!(attached_readiness
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "mock_binding_active"));
    assert!(attached_readiness
        .warnings
        .iter()
        .any(|issue| issue.code == "operational_value_not_estimated"));
    assert!(attached_readiness
        .warnings
        .iter()
        .any(|issue| issue.code == "missing_replay_fixture"));
    save_workflow_node_fixture(
        attached.workflow_path.clone(),
        WorkflowNodeFixture {
            id: "fixture-attached-model".to_string(),
            node_id: "attached-model".to_string(),
            name: "Attached model sample".to_string(),
            input: Some(json!({"payload": "hello"})),
            output: Some(json!({"answer": "world"})),
            schema_hash: None,
            node_config_hash: None,
            source_run_id: Some("run-attached".to_string()),
            pinned: None,
            stale: Some(false),
            validation_status: None,
            validation_message: None,
            created_at_ms: now_ms(),
        },
    )
    .expect("fixture should save");
    let attached_with_fixture =
        validate_workflow_execution_readiness(attached.workflow_path).expect("readiness rerun");
    assert!(!attached_with_fixture.warnings.iter().any(|issue| {
        issue.code == "missing_replay_fixture" && issue.node_id.as_deref() == Some("attached-model")
    }));

    let mcp = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "MCP Activation".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("mcp workflow should create");
    let source = workflow_node("mcp-source", "source", "Input", 120, 180, "Input", "manual");
    let mut tool = workflow_node(
        "mcp-tool",
        "plugin_tool",
        "MCP search",
        360,
        180,
        "Tool",
        "mcp.search",
    );
    let tool_binding = logic_mut(&mut tool)
        .get_mut("toolBinding")
        .and_then(Value::as_object_mut)
        .expect("tool binding");
    tool_binding.insert("bindingKind".to_string(), json!("mcp_tool"));
    tool_binding.insert("mockBinding".to_string(), json!(false));
    tool_binding.insert("credentialReady".to_string(), json!(true));
    let output = workflow_node(
        "mcp-output",
        "output",
        "Output",
        620,
        180,
        "Output",
        "summary",
    );
    let mut mcp_workflow = mcp.workflow.clone();
    mcp_workflow.nodes = vec![source, tool, output];
    mcp_workflow.edges = vec![
        workflow_edge("edge-mcp-source-tool", "mcp-source", "mcp-tool"),
        workflow_edge("edge-mcp-tool-output", "mcp-tool", "mcp-output"),
    ];
    save_workflow_project(mcp.workflow_path.clone(), mcp_workflow)
        .expect("mcp workflow should save");
    save_workflow_tests(
        mcp.workflow_path.clone(),
        vec![WorkflowTestCase {
            id: "test-mcp-tool".to_string(),
            name: "MCP tool exists".to_string(),
            target_node_ids: vec!["mcp-tool".to_string()],
            target_subgraph_id: None,
            assertion: WorkflowTestAssertion {
                kind: "node_exists".to_string(),
                expected: None,
                expression: None,
            },
            status: Some("idle".to_string()),
            last_message: None,
        }],
    )
    .expect("mcp tests should save");
    let mcp_readiness =
        validate_workflow_execution_readiness(mcp.workflow_path).expect("mcp readiness");
    assert!(mcp_readiness
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "mcp_access_not_reviewed"));
}

#[test]
fn workflow_activation_readiness_blocks_unbound_coding_budget_recovery_templates() {
    let root = temp_root("activation-coding-budget-recovery-template");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Coding Budget Recovery Template".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let trigger = workflow_node(
        "recovery-trigger",
        "trigger",
        "Trigger",
        80,
        160,
        "Trigger",
        "manual",
    );
    let output = workflow_node(
        "recovery-output",
        "output",
        "Output",
        640,
        160,
        "Output",
        "markdown",
    );
    let mut recovery = workflow_node(
        "budget-recovery-template",
        "runtime_coding_tool_budget_recovery",
        "Budget recovery template",
        320,
        160,
        "Recovery",
        "budget",
    );
    logic_mut(&mut recovery).insert(
        "runtimeCodingToolBudgetRecoveryEndpoint".to_string(),
        json!("/v1/runs/{runId}/coding-tool-budget-recovery"),
    );
    logic_mut(&mut recovery).insert(
        "runtimeCodingToolBudgetRecoveryRunIdField".to_string(),
        json!("runId"),
    );
    logic_mut(&mut recovery).insert(
        "runtimeCodingToolBudgetRecoveryThreadIdField".to_string(),
        json!("threadId"),
    );
    logic_mut(&mut recovery).insert(
        "runtimeCodingToolBudgetRecoveryApprovalIdField".to_string(),
        json!("approvalId"),
    );
    logic_mut(&mut recovery).insert(
        "runtimeCodingToolBudgetRecoveryTargetNodeIdsField".to_string(),
        json!("targetNodeIds"),
    );
    logic_mut(&mut recovery).insert(
        "runtimeCodingToolBudgetRecoveryPolicyInputField".to_string(),
        json!("recoveryPolicy"),
    );
    logic_mut(&mut recovery).insert(
        "runtimeCodingToolBudgetRecoveryAction".to_string(),
        json!("retry_approved"),
    );
    logic_mut(&mut recovery).insert(
        "runtimeCodingToolBudgetRecoveryPolicy".to_string(),
        json!({
            "schemaVersion": "ioi.workflow.coding-tool-budget-recovery-policy.v1",
            "source": "react_flow_template",
            "approvalScope": "target_nodes",
            "operatorRole": "operator",
            "retryLimit": 1,
            "ttlMs": 900000,
            "requiresApproval": true,
            "allowOverride": true,
            "targetNodeIds": [],
            "sourceNodeIds": []
        }),
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![trigger, recovery, output];
    workflow.edges = vec![
        workflow_edge(
            "edge-trigger-recovery",
            "recovery-trigger",
            "budget-recovery-template",
        ),
        workflow_edge(
            "edge-recovery-output",
            "budget-recovery-template",
            "recovery-output",
        ),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow.clone())
        .expect("workflow should save");
    save_workflow_tests(
        bundle.workflow_path.clone(),
        vec![WorkflowTestCase {
            id: "test-recovery-output".to_string(),
            name: "Recovery output exists".to_string(),
            target_node_ids: vec!["recovery-output".to_string()],
            target_subgraph_id: None,
            assertion: WorkflowTestAssertion {
                kind: "node_exists".to_string(),
                expected: None,
                expression: None,
            },
            status: Some("idle".to_string()),
            last_message: None,
        }],
    )
    .expect("tests should save");

    let blocked = validate_workflow_execution_readiness(bundle.workflow_path.clone())
        .expect("readiness should run");
    let binding_issue_codes = blocked
        .execution_readiness_issues
        .iter()
        .filter(|issue| issue.node_id.as_deref() == Some("budget-recovery-template"))
        .filter(|issue| {
            issue
                .code
                .starts_with("missing_runtime_coding_tool_budget_recovery_")
        })
        .map(|issue| issue.code.as_str())
        .collect::<Vec<_>>();
    assert!(binding_issue_codes.contains(
        &"missing_runtime_coding_tool_budget_recovery_run_binding"
    ));
    assert!(binding_issue_codes.contains(
        &"missing_runtime_coding_tool_budget_recovery_thread_binding"
    ));
    assert!(binding_issue_codes.contains(
        &"missing_runtime_coding_tool_budget_recovery_approval_binding"
    ));
    assert!(binding_issue_codes.contains(
        &"missing_runtime_coding_tool_budget_recovery_target_binding"
    ));
    assert!(binding_issue_codes.contains(
        &"missing_runtime_coding_tool_budget_recovery_policy_binding"
    ));

    let recovery_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("budget-recovery-template"))
        .expect("recovery node should exist");
    logic_mut(recovery_node).insert(
        "runtimeCodingToolBudgetRecoveryRunId".to_string(),
        json!("run-template"),
    );
    logic_mut(recovery_node).insert(
        "runtimeCodingToolBudgetRecoveryThreadId".to_string(),
        json!("thread-template"),
    );
    logic_mut(recovery_node).insert(
        "runtimeCodingToolBudgetRecoveryApprovalId".to_string(),
        json!("approval-template"),
    );
    logic_mut(recovery_node).insert(
        "runtimeCodingToolBudgetRecoveryTargetNodeIds".to_string(),
        json!(["node.apply_patch"]),
    );
    logic_mut(recovery_node).insert(
        "runtimeCodingToolBudgetRecoveryPolicy".to_string(),
        json!({
            "schemaVersion": "ioi.workflow.coding-tool-budget-recovery-policy.v1",
            "source": "react_flow_fixed",
            "approvalScope": "target_nodes",
            "operatorRole": "operator",
            "retryLimit": 1,
            "ttlMs": 900000,
            "requiresApproval": true,
            "allowOverride": true,
            "targetNodeIds": ["node.apply_patch"],
            "sourceNodeIds": ["node.apply_patch"]
        }),
    );
    save_workflow_project(bundle.workflow_path.clone(), workflow)
        .expect("bound workflow should save");
    let bound = validate_workflow_execution_readiness(bundle.workflow_path)
        .expect("readiness should rerun");
    assert!(!bound.execution_readiness_issues.iter().any(|issue| {
        issue.node_id.as_deref() == Some("budget-recovery-template")
            && issue
                .code
                .starts_with("missing_runtime_coding_tool_budget_recovery_")
    }));
}

#[test]
fn restore_workflow_revision_restores_single_workflow_file_from_git() {
    let root = temp_root("git-workflow-restore");
    run_git(&root, &["init"]).expect("git init");
    run_git(&root, &["config", "user.name", "Autopilot Test"]).expect("git user");
    run_git(
        &root,
        &["config", "user.email", "autopilot-test@example.com"],
    )
    .expect("git email");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Git Revision Restore".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow should create");
    run_git(&root, &["add", "--", ".agents/workflows"]).expect("git add workflow");
    run_git(&root, &["commit", "-m", "Initial workflow"]).expect("git commit workflow");
    let initial_revision = run_git(&root, &["rev-parse", "HEAD"]).expect("git rev parse");
    let workflow_path = PathBuf::from(&bundle.workflow_path);
    let relative_workflow_path = workflow_path
        .strip_prefix(&root)
        .expect("workflow path should be inside root")
        .to_string_lossy()
        .replace('\\', "/");
    let initial_workflow_content_hash = workflow_project_content_hash(&bundle.workflow);

    let mut mutated = bundle.workflow.clone();
    mutated.metadata.name = "Mutated Workflow".to_string();
    save_workflow_project(bundle.workflow_path.clone(), mutated).expect("mutated save");
    let changed = load_workflow_bundle(bundle.workflow_path.clone()).expect("changed load");
    assert_eq!(changed.workflow.metadata.name, "Mutated Workflow");

    let revision_binding = WorkflowRevisionBinding {
        schema_version: "workflow.revision-binding.v1".to_string(),
        workflow_path: relative_workflow_path.clone(),
        repo_root: Some(root.display().to_string()),
        branch: Some("master".to_string()),
        base_revision: None,
        activated_revision: Some(initial_revision.clone()),
        workflow_content_hash: initial_workflow_content_hash.clone(),
        proposal_id: None,
        activation_id: Some("activation:git-backed".to_string()),
        rollback_activation_id: None,
        rollback_revision: None,
        revision_source: "git".to_string(),
        created_at_ms: now_ms(),
    };
    let dry_run = restore_workflow_revision(WorkflowRevisionRestoreRequest {
        workflow_path: bundle.workflow_path.clone(),
        revision_binding: revision_binding.clone(),
        expected_workflow_content_hash: Some(initial_workflow_content_hash.clone()),
        dry_run: true,
    })
    .expect("dry-run restore command should return");
    assert!(dry_run.restored, "{:?}", dry_run.blockers);
    assert!(dry_run.dry_run);
    assert!(dry_run.hash_verified);
    assert!(dry_run
        .receipt_binding_ref
        .as_deref()
        .unwrap_or_default()
        .starts_with("workflow_restore_canary:"));
    assert_eq!(
        dry_run.actual_workflow_content_hash.as_deref(),
        Some(initial_workflow_content_hash.as_str())
    );
    assert_eq!(
        dry_run.bundle.as_ref().unwrap().workflow.metadata.name,
        "Git Revision Restore"
    );
    let still_mutated =
        load_workflow_bundle(bundle.workflow_path.clone()).expect("dry run load");
    assert_eq!(still_mutated.workflow.metadata.name, "Mutated Workflow");

    let mismatch = restore_workflow_revision(WorkflowRevisionRestoreRequest {
        workflow_path: bundle.workflow_path.clone(),
        revision_binding: revision_binding.clone(),
        expected_workflow_content_hash: Some("stable-fnv1a32:wrong".to_string()),
        dry_run: false,
    })
    .expect("mismatched restore command should return");
    assert!(!mismatch.restored);
    assert!(!mismatch.hash_verified);
    assert!(mismatch
        .receipt_binding_ref
        .as_deref()
        .unwrap_or_default()
        .starts_with("workflow_restore_canary:"));
    assert!(mismatch
        .blockers
        .contains(&"workflow_content_hash_mismatch".to_string()));
    assert_eq!(
        mismatch.actual_workflow_content_hash.as_deref(),
        Some(initial_workflow_content_hash.as_str())
    );
    let still_mutated =
        load_workflow_bundle(bundle.workflow_path.clone()).expect("mismatch load");
    assert_eq!(still_mutated.workflow.metadata.name, "Mutated Workflow");

    let restore = restore_workflow_revision(WorkflowRevisionRestoreRequest {
        workflow_path: bundle.workflow_path.clone(),
        revision_binding,
        expected_workflow_content_hash: Some(initial_workflow_content_hash.clone()),
        dry_run: false,
    })
    .expect("restore command should return");

    assert!(restore.restored, "{:?}", restore.blockers);
    assert!(restore.hash_verified);
    assert_eq!(restore.receipt_binding_ref, dry_run.receipt_binding_ref);
    assert_eq!(restore.restore_strategy, "git_show_file_restore");
    assert_eq!(
        restore.actual_workflow_content_hash.as_deref(),
        Some(initial_workflow_content_hash.as_str())
    );
    assert_eq!(
        restore.relative_workflow_path.as_deref(),
        Some(relative_workflow_path.as_str())
    );
    assert_eq!(restore.restored_revision.as_deref(), Some(initial_revision.as_str()));
    assert!(restore.file_sha256.is_some());
    assert_eq!(
        restore.bundle.as_ref().unwrap().workflow.metadata.name,
        "Git Revision Restore"
    );
    let loaded = load_workflow_bundle(bundle.workflow_path).expect("restored load");
    assert_eq!(loaded.workflow.metadata.name, "Git Revision Restore");
}

#[test]
fn workflow_activation_readiness_blocks_live_trigger_and_missing_production_fixtures() {
    let root = temp_root("activation-live-readiness");
    let event_bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Event Trigger Activation".to_string(),
        workflow_kind: "event_workflow".to_string(),
        execution_mode: "hybrid".to_string(),
        template_id: None,
    })
    .expect("event workflow should create");
    let mut trigger = workflow_node(
        "event-trigger",
        "trigger",
        "Incoming message",
        120,
        180,
        "Trigger",
        "event",
    );
    logic_mut(&mut trigger).insert("triggerKind".to_string(), json!("event"));
    logic_mut(&mut trigger).insert("eventSourceRef".to_string(), json!("mock.slack.message"));
    logic_mut(&mut trigger).insert("runtimeReady".to_string(), json!(false));
    let output = workflow_node(
        "event-output",
        "output",
        "Output",
        380,
        180,
        "Output",
        "summary",
    );
    let mut event_workflow = event_bundle.workflow.clone();
    event_workflow.global_config["environmentProfile"] = json!({
        "target": "production",
        "credentialScope": "production",
        "mockBindingPolicy": "allow"
    });
    event_workflow.nodes = vec![trigger, output];
    event_workflow.edges = vec![workflow_edge(
        "edge-event-output",
        "event-trigger",
        "event-output",
    )];
    save_workflow_project(event_bundle.workflow_path.clone(), event_workflow)
        .expect("event workflow should save");
    save_workflow_tests(
        event_bundle.workflow_path.clone(),
        vec![WorkflowTestCase {
            id: "test-event-trigger".to_string(),
            name: "Event trigger exists".to_string(),
            target_node_ids: vec!["event-trigger".to_string()],
            target_subgraph_id: None,
            assertion: WorkflowTestAssertion {
                kind: "node_exists".to_string(),
                expected: None,
                expression: None,
            },
            status: Some("idle".to_string()),
            last_message: None,
        }],
    )
    .expect("event tests should save");
    let event_readiness = validate_workflow_execution_readiness(event_bundle.workflow_path.clone())
        .expect("event readiness should run");
    assert!(event_readiness
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "unsupported_live_trigger"));

    let function_bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("Production Function Readiness".to_string()),
    })
    .expect("function workflow should instantiate");
    let mut function_workflow = function_bundle.workflow.clone();
    function_workflow.global_config["environmentProfile"] = json!({
        "target": "production",
        "credentialScope": "production",
        "mockBindingPolicy": "allow"
    });
    save_workflow_project(function_bundle.workflow_path.clone(), function_workflow)
        .expect("function workflow should save");
    let missing_fixture =
        validate_workflow_execution_readiness(function_bundle.workflow_path.clone())
            .expect("production readiness should run");
    assert!(missing_fixture
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "missing_replay_fixture"));

    save_workflow_node_fixture(
        function_bundle.workflow_path.clone(),
        WorkflowNodeFixture {
            id: "fixture-function-summarize".to_string(),
            node_id: "function-summarize".to_string(),
            name: "Function replay sample".to_string(),
            input: Some(json!({"items": [{"path": "a.rs"}]})),
            output: Some(json!({"summary": "ok", "count": 1})),
            schema_hash: None,
            node_config_hash: None,
            source_run_id: Some("run-function".to_string()),
            pinned: Some(true),
            stale: Some(false),
            validation_status: Some("passed".to_string()),
            validation_message: None,
            created_at_ms: now_ms(),
        },
    )
    .expect("fixture should save");
    let with_fixture = validate_workflow_execution_readiness(function_bundle.workflow_path)
        .expect("production readiness should rerun");
    assert!(!with_fixture
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "missing_replay_fixture"));
}

#[test]
fn workflow_retry_preserves_failed_attempt_evidence() {
    let root = temp_root("retry");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "basic-agent-answer".to_string(),
        name: Some("Retry Evidence".to_string()),
    })
    .expect("template should instantiate");
    let mut workflow = bundle.workflow.clone();
    let model_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("model-answer"))
        .expect("model node exists");
    let logic = logic_mut(model_node);
    logic.insert("failUntilAttempt".to_string(), json!(1));
    logic.insert("retry".to_string(), json!({ "maxAttempts": 2 }));
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run = run_workflow_project(bundle.workflow_path, None).expect("run should execute");
    assert_eq!(run.summary.status, "passed");
    let model_attempts = run
        .node_runs
        .iter()
        .filter(|node_run| node_run.node_id == "model-answer")
        .collect::<Vec<_>>();
    assert_eq!(model_attempts.len(), 2);
    assert_eq!(model_attempts[0].attempt, 1);
    assert_eq!(model_attempts[0].status, "error");
    assert_eq!(model_attempts[1].attempt, 2);
    assert_eq!(model_attempts[1].status, "success");
}

#[test]
fn workflow_dogfood_suite_creates_and_runs_heavy_targets() {
    let root = temp_root("dogfood-suite");
    let result = run_workflow_dogfood_suite(
        root.display().to_string(),
        "heavy-runtime".to_string(),
        None,
    )
    .expect("dogfood suite should run");
    assert_eq!(result.status, "passed");
    assert_eq!(result.workflow_paths.len(), 7);
    assert!(PathBuf::from(&result.gap_ledger_path).exists());
}

#[test]
fn workflow_portable_package_exports_and_imports_bundle_sidecars() {
    let root = temp_root("portable-package");
    let mut bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "heavy-media-transform".to_string(),
        name: Some("Portable Media Transform".to_string()),
    })
    .expect("workflow should instantiate");
    bundle.workflow.global_config["workflowChromeLocale"] = json!("es-ES");
    save_workflow_project(bundle.workflow_path.clone(), bundle.workflow.clone())
        .expect("workflow chrome locale should persist before export");
    let function_node_id = "function-svg-trace".to_string();
    materialize_workflow_function(bundle.workflow_path.clone(), function_node_id, None)
        .expect("function should materialize");
    save_workflow_node_fixture(
        bundle.workflow_path.clone(),
        WorkflowNodeFixture {
            id: "fixture-media-output".to_string(),
            node_id: "output-media-svg".to_string(),
            name: "SVG sample".to_string(),
            input: Some(json!({"image": "jpg"})),
            output: Some(json!({"svg": "<svg />"})),
            schema_hash: Some("schema-portable".to_string()),
            node_config_hash: Some("config-portable".to_string()),
            source_run_id: None,
            pinned: None,
            stale: Some(false),
            validation_status: None,
            validation_message: None,
            created_at_ms: now_ms(),
        },
    )
    .expect("fixture should save");
    let run = run_workflow_project(bundle.workflow_path.clone(), None)
        .expect("workflow should run before export");
    assert_eq!(run.summary.status, "passed");

    let package =
        export_workflow_package(bundle.workflow_path.clone(), None).expect("package should export");
    assert_eq!(
        package.manifest.schema_version,
        "workflow.portable-package.v1"
    );
    assert_eq!(
        package.manifest.workflow_chrome_locale.as_deref(),
        Some("es-ES")
    );
    assert!(PathBuf::from(&package.manifest_path).exists());
    assert!(package
        .manifest
        .files
        .iter()
        .any(|file| file.role == "workflow"));
    assert!(package
        .manifest
        .files
        .iter()
        .any(|file| file.role == "tests"));
    assert!(package
        .manifest
        .files
        .iter()
        .any(|file| file.role == "fixtures"));
    assert!(package
        .manifest
        .files
        .iter()
        .any(|file| file.role == "function"));
    assert!(package
        .manifest
        .files
        .iter()
        .any(|file| file.role == "binding_manifest_sidecar"));
    assert!(package
        .manifest
        .files
        .iter()
        .any(|file| file.role == "binding_manifest"));
    assert!(package
        .manifest
        .files
        .iter()
        .any(|file| file.role == "run_summary"));
    assert!(package
        .manifest
        .files
        .iter()
        .any(|file| file.role == "checkpoint"));
    assert!(package
        .manifest
        .files
        .iter()
        .any(|file| file.role == "output_manifest"));
    assert!(package
        .manifest
        .files
        .iter()
        .any(|file| file.role == "hidden_evidence_schema"));
    assert!(package
        .manifest
        .files
        .iter()
        .all(|file| file.sha256.len() == 64));

    let import_root = temp_root("portable-package-import");
    let package_path = package.package_path.clone();
    let imported = import_workflow_package(ImportWorkflowPackageRequest {
        package_path: package_path.clone(),
        project_root: import_root.display().to_string(),
        name: Some("Imported Media Transform".to_string()),
    })
    .expect("package should import");
    assert!(PathBuf::from(&imported.workflow_path).exists());
    assert!(PathBuf::from(&imported.tests_path).exists());
    assert_eq!(imported.workflow.metadata.name, "Imported Media Transform");
    assert_eq!(imported.workflow.nodes.len(), bundle.workflow.nodes.len());
    assert!(workflow_fixtures_path(&PathBuf::from(&imported.workflow_path)).exists());
    assert!(workflow_functions_dir(&PathBuf::from(&imported.workflow_path)).exists());
    let imported_binding_manifest_path =
        workflow_binding_manifest_path(&PathBuf::from(&imported.workflow_path));
    assert!(imported_binding_manifest_path.exists());
    let imported_binding_manifest: WorkflowBindingManifest =
        read_json_file(&imported_binding_manifest_path).expect("binding manifest should import");
    assert_eq!(
        imported_binding_manifest.workflow_slug,
        "imported-media-transform"
    );
    let imported_package = imported
        .imported_package
        .as_ref()
        .expect("imported package manifest should round-trip to workbench");
    assert_eq!(imported_package.package_path, package_path);
    assert_eq!(
        imported_package.imported_workflow_path.as_deref(),
        Some(imported.workflow_path.as_str())
    );
    assert_eq!(
        imported_package.manifest.workflow_chrome_locale.as_deref(),
        Some("es-ES")
    );
    assert_eq!(
        imported
            .workflow
            .global_config
            .get("workflowChromeLocale")
            .and_then(Value::as_str),
        Some("es-ES")
    );
    assert_eq!(
        imported_package.manifest.source_workflow_path,
        bundle.workflow_path
    );
    let evidence = list_workflow_evidence(imported.workflow_path).expect("evidence should load");
    assert!(evidence.iter().any(|item| item.kind == "package"));
    assert!(evidence
        .iter()
        .any(|item| item.kind == "binding_manifest" && item.path.is_none()));
}

#[test]
fn workflow_portable_package_preserves_harness_lineage_metadata() {
    let root = temp_root("portable-harness");
    let mut bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Harness Fork".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "hybrid".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");
    bundle.workflow.metadata.harness = Some(json!({
        "schemaVersion": "workflow.harness.v1",
        "harnessWorkflowId": "default-agent-harness",
        "harnessVersion": "2026.04.default-harness.v1",
        "harnessHash": "sha256:default-agent-harness-component-projection-v1",
        "templateName": "Default Agent Harness",
        "blessed": false,
        "forkable": false,
        "forkedFrom": {
            "harnessWorkflowId": "default-agent-harness",
            "harnessVersion": "2026.04.default-harness.v1",
            "harnessHash": "sha256:default-agent-harness-component-projection-v1"
        },
        "packageManifest": {
            "schemaVersion": "workflow.harness.package-evidence-manifest.v1",
            "packageName": "harness-fork",
            "workflowId": "harness-fork",
            "harnessWorkflowId": "default-agent-harness",
            "activationId": "activation:harness-fork:sandbox",
            "activationState": "validated",
            "harnessHash": "sha256:default-agent-harness-component-projection-v1",
            "workflowContentHash": "stable-fnv1a32:package",
            "rollbackTarget": "activation:default-agent-harness:blessed-readonly",
            "componentVersionSet": {
                "ioi.agent-harness.planner.v1": "1.0.0"
            },
            "evidenceRefs": [
                "harness-canary-boundary:default-agent-harness:cognition"
            ],
            "receiptRefs": [
                "workflow_restore_canary:package"
            ],
            "replayFixtureRefs": [
                "runtime-evidence:default:canary-fixture:planner"
            ],
            "nodeAttemptIds": [
                "harness-worker-handoff:attempt:launch:package"
            ],
            "canaryBoundaryIds": [
                "harness-canary-boundary:default-agent-harness:cognition"
            ],
            "rollbackDrillIds": [
                "harness-canary-rollback-drill:default"
            ],
            "workerHandoffNodeAttemptIds": [
                "harness-worker-handoff:attempt:launch:package"
            ],
            "workerHandoffReceiptIds": [
                "harness-worker-handoff:receipt:launch:package"
            ],
            "rollbackRestoreReceiptRefs": [
                "workflow_restore_canary:package"
            ],
            "deepLinks": [
                {
                    "kind": "rollback_restore",
                    "ref": "workflow_restore_canary:package",
                    "hash": "#harness-workbench?panel=settings&activationGateId=rollback-restore&activationGateReceiptRef=workflow_restore_canary%3Apackage"
                }
            ],
            "createdAtMs": 1
        },
        "validationGates": ["component_contracts_present"],
        "aiMutationMode": "proposal_only",
        "componentIds": ["ioi.agent-harness.planner.v1"],
        "slotIds": ["slot.model-policy"]
    }));
    bundle.workflow.metadata.worker_harness_binding = Some(json!({
        "harnessWorkflowId": "harness-fork",
        "harnessActivationId": "activation:harness-fork:sandbox",
        "harnessHash": "sha256:default-agent-harness-component-projection-v1",
        "source": "fork"
    }));
    save_workflow_project(bundle.workflow_path.clone(), bundle.workflow)
        .expect("harness workflow should save");

    let package =
        export_workflow_package(bundle.workflow_path.clone(), None).expect("package should export");
    assert_eq!(
        package
            .manifest
            .harness
            .as_ref()
            .and_then(|value| value.get("aiMutationMode"))
            .and_then(Value::as_str),
        Some("proposal_only")
    );
    assert_eq!(
        package
            .manifest
            .worker_harness_binding
            .as_ref()
            .and_then(|value| value.get("harnessActivationId"))
            .and_then(Value::as_str),
        Some("activation:harness-fork:sandbox")
    );
    assert!(package
        .manifest
        .files
        .iter()
        .any(|file| file.role == "harness_package_manifest"));
    assert_eq!(
        package
            .manifest
            .harness_package_manifest
            .as_ref()
            .and_then(|value| value.get("schemaVersion"))
            .and_then(Value::as_str),
        Some("workflow.harness.package-evidence-manifest.v1")
    );
    assert_eq!(
        package
            .manifest
            .harness_package_manifest
            .as_ref()
            .and_then(|value| value.get("workerHandoffNodeAttemptIds"))
            .and_then(Value::as_array)
            .map(Vec::len),
        Some(1)
    );
    assert!(PathBuf::from(&package.package_path)
        .join("harness-package-evidence.json")
        .exists());

    let import_root = temp_root("portable-harness-import");
    let package_path = package.package_path.clone();
    let imported = import_workflow_package(ImportWorkflowPackageRequest {
        package_path: package_path.clone(),
        project_root: import_root.display().to_string(),
        name: Some("Imported Harness Fork".to_string()),
    })
    .expect("harness package should import");
    let imported_package = imported
        .imported_package
        .as_ref()
        .expect("harness package manifest should be returned for import review");
    assert_eq!(imported_package.package_path, package_path);
    assert_eq!(
        imported_package
            .manifest
            .harness_package_manifest
            .as_ref()
            .and_then(|value| value.get("schemaVersion"))
            .and_then(Value::as_str),
        Some("workflow.harness.package-evidence-manifest.v1")
    );
    assert_eq!(
        imported
            .workflow
            .metadata
            .harness
            .as_ref()
            .and_then(|value| value.get("packageManifest"))
            .and_then(|value| value.get("schemaVersion"))
            .and_then(Value::as_str),
        Some("workflow.harness.package-evidence-manifest.v1")
    );
    assert!(
        imported
            .workflow
            .metadata
            .harness
            .as_ref()
            .and_then(|value| value.get("packageManifest"))
            .and_then(|value| value.get("deepLinks"))
            .and_then(Value::as_array)
            .and_then(|links| links.first())
            .and_then(|value| value.get("hash"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("activationGateId=rollback-restore")
    );
}

#[test]
fn workflow_activation_readiness_blocks_unvalidated_harness_fork_and_accepts_canary_record() {
    let root = temp_root("harness-fork-activation");
    let mut bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Harness Fork Activation".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "hybrid".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    bundle.workflow.metadata.harness = Some(json!({
        "schemaVersion": "workflow.harness.v1",
        "harnessWorkflowId": "harness-fork",
        "harnessVersion": "2026.04.default-harness.v1",
        "harnessHash": "sha256:default-agent-harness-component-projection-v1",
        "executionMode": "projection",
        "templateName": "Default Agent Harness Fork",
        "blessed": false,
        "forkable": false,
        "forkedFrom": {
            "harnessWorkflowId": "default-agent-harness",
            "harnessVersion": "2026.04.default-harness.v1",
            "harnessHash": "sha256:default-agent-harness-component-projection-v1"
        },
        "activationState": "blocked",
        "activationRecord": {
            "schemaVersion": "workflow.harness.activation.v1",
            "workflowId": "harness-fork",
            "harnessWorkflowId": "harness-fork",
            "harnessHash": "sha256:default-agent-harness-component-projection-v1",
            "activationState": "blocked",
            "activationBlockers": ["harness_activation_not_validated", "canary_not_run"],
            "componentVersionSet": {"ioi.agent-harness.planner.v1": "1.0.0"},
            "policyPosture": "proposal_only",
            "canaryStatus": "not_run",
            "rollbackTarget": "activation:default-agent-harness:blessed-readonly",
            "rollbackAvailable": false,
            "liveAuthorityTransferred": false,
            "evidenceRefs": ["proposal-harness-fork-activation-gates"]
        },
        "validationGates": ["component_contracts_present"],
        "aiMutationMode": "proposal_only",
        "componentIds": ["ioi.agent-harness.planner.v1"],
        "slotIds": []
    }));
    bundle.workflow.metadata.worker_harness_binding = Some(json!({
        "harnessWorkflowId": "harness-fork",
        "harnessHash": "sha256:default-agent-harness-component-projection-v1",
        "executionMode": "projection",
        "source": "fork"
    }));
    save_workflow_project(bundle.workflow_path.clone(), bundle.workflow.clone())
        .expect("blocked harness fork should save");
    let blocked_readiness = validate_workflow_execution_readiness(bundle.workflow_path.clone())
        .expect("blocked harness readiness should run");
    assert!(blocked_readiness
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "harness_activation_not_validated"));

    let activation_id = "activation:harness-fork:validated-canary:default-agent";
    let valid_worker_binding = json!({
        "harnessWorkflowId": "harness-fork",
        "harnessActivationId": activation_id,
        "harnessHash": "sha256:default-agent-harness-component-projection-v1",
        "executionMode": "gated",
        "source": "fork"
    });
    let valid_worker_binding_registry_record = json!({
        "schemaVersion": "workflow.harness.worker-binding-registry.v1",
        "registryRecordId": "harness-worker-binding-registry:harness-fork:validated-canary:default-agent",
        "workflowId": "harness-fork",
        "activationId": activation_id,
        "activationHash": "sha256:default-agent-harness-component-projection-v1",
        "harnessHash": "sha256:default-agent-harness-component-projection-v1",
        "componentVersionSet": {"ioi.agent-harness.planner.v1": "1.0.0"},
        "rollbackTarget": "activation:default-agent-harness:blessed-readonly",
        "readinessProofId": "harness-live-promotion-readiness:harness-fork:validated-canary:default-agent",
        "canaryResultId": "harness-canary-result:harness-fork:validated-canary:default-agent:passed",
        "policyDecision": "canary",
        "bindingStatus": "canary",
        "blockers": ["fork_activation_not_live_default"],
        "workerBinding": valid_worker_binding.clone()
    });
    let valid_harness = bundle
        .workflow
        .metadata
        .harness
        .as_mut()
        .expect("harness metadata should exist");
    valid_harness["activationId"] = json!(activation_id);
    valid_harness["activationState"] = json!("validated");
    valid_harness["activationRecord"] = json!({
        "schemaVersion": "workflow.harness.activation.v1",
        "workflowId": "harness-fork",
        "harnessWorkflowId": "harness-fork",
        "activationId": activation_id,
        "harnessHash": "sha256:default-agent-harness-component-projection-v1",
        "activationState": "validated",
        "activationBlockers": [],
        "componentVersionSet": {"ioi.agent-harness.planner.v1": "1.0.0"},
        "policyPosture": "canary",
        "canaryStatus": "passed",
        "rollbackTarget": "activation:default-agent-harness:blessed-readonly",
        "rollbackAvailable": true,
        "liveAuthorityTransferred": false,
        "evidenceRefs": ["run-harness-fork-canary"],
        "workerBinding": valid_worker_binding.clone(),
        "workerBindingRegistryRecord": valid_worker_binding_registry_record
    });
    bundle.workflow.metadata.worker_harness_binding = Some(valid_worker_binding);
    save_workflow_project(bundle.workflow_path.clone(), bundle.workflow)
        .expect("validated harness fork should save");
    let validated_readiness = validate_workflow_execution_readiness(bundle.workflow_path)
        .expect("validated harness readiness should run");
    assert!(!validated_readiness
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "harness_activation_not_validated"));
}

#[test]
fn workflow_run_records_harness_attempts_for_runtime_bound_nodes() {
    let root = temp_root("harness-run-attempts");
    let mut bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Harness Attempt Run".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "hybrid".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    bundle.workflow.metadata.harness = Some(json!({
        "schemaVersion": "workflow.harness.v1",
        "harnessWorkflowId": "default-agent-harness",
        "harnessVersion": "2026.04.default-harness.v1",
        "harnessHash": "sha256:default-agent-harness-component-projection-v1",
        "executionMode": "projection",
        "templateName": "Default Agent Harness",
        "blessed": true,
        "forkable": true,
        "validationGates": ["component_contracts_present"],
        "aiMutationMode": "proposal_only",
        "componentIds": ["ioi.agent-harness.planner.v1"],
        "slotIds": ["slot.model-policy"]
    }));
    bundle.workflow.metadata.worker_harness_binding = Some(json!({
        "harnessWorkflowId": "default-agent-harness",
        "harnessActivationId": "activation:default-agent-harness:blessed-readonly",
        "harnessHash": "sha256:default-agent-harness-component-projection-v1",
        "executionMode": "projection",
        "source": "default"
    }));

    let mut planner = workflow_function_node(
        "harness.planner",
        "Planner",
        120,
        180,
        "return { status: 'planned', receipt: 'plan-id-1' };",
    );
    planner
        .as_object_mut()
        .expect("node object")
        .insert(
            "runtimeBinding".to_string(),
            json!({
                "componentId": "ioi.agent-harness.planner.v1",
                "componentVersion": "1.0.0",
                "componentKind": "planner",
                "executionMode": "projection",
                "readiness": "projection_only",
                "kernelRef": "crates/services/src/agentic/runtime/service/planning/planner",
                "slotIds": ["slot.model-policy"],
                "evidenceEventKinds": ["PlanReceipt", "KernelEvent::PlanReceipt"],
                "receiptKinds": ["plan_id", "planner_policy_hash"],
                "replayEnvelope": {
                    "deterministicEnvelope": true,
                    "capturesInput": true,
                    "capturesOutput": true,
                    "capturesPolicyDecision": false,
                    "determinism": "deterministic",
                    "redactionPolicy": "runtime_redacted"
                },
                "replay": {
                    "deterministicEnvelope": true,
                    "capturesInput": true,
                    "capturesOutput": true,
                    "capturesPolicyDecision": false
                }
            }),
        );
    bundle.workflow.nodes = vec![planner];
    save_workflow_project(bundle.workflow_path.clone(), bundle.workflow)
        .expect("harness workflow should save");

    let result = run_workflow_project(bundle.workflow_path.clone(), None)
        .expect("harness workflow should run");
    assert_eq!(result.summary.status, "passed");
    assert_eq!(result.harness_attempts.len(), 1);
    assert_eq!(result.harness_gated_cluster_runs.len(), 4);
    assert_eq!(
        result.harness_attempts[0]
            .get("workflowNodeId")
            .and_then(Value::as_str),
        Some("harness.planner")
    );
    assert_eq!(
        result.harness_attempts[0]
            .get("executionMode")
            .and_then(Value::as_str),
        Some("projection")
    );
    assert!(result.node_runs[0].harness_attempt.is_some());
    assert!(result.harness_attempts[0].get("inputHash").is_some());
    assert!(result.harness_attempts[0].get("outputHash").is_some());
    let cognition_gate = result
        .harness_gated_cluster_runs
        .iter()
        .find(|run| run.get("clusterId").and_then(Value::as_str) == Some("cognition"))
        .expect("cognition gate");
    let routing_model_gate = result
        .harness_gated_cluster_runs
        .iter()
        .find(|run| run.get("clusterId").and_then(Value::as_str) == Some("routing_model"))
        .expect("routing/model gate");
    let verification_output_gate = result
        .harness_gated_cluster_runs
        .iter()
        .find(|run| run.get("clusterId").and_then(Value::as_str) == Some("verification_output"))
        .expect("verification/output gate");
    let authority_tooling_gate = result
        .harness_gated_cluster_runs
        .iter()
        .find(|run| run.get("clusterId").and_then(Value::as_str) == Some("authority_tooling"))
        .expect("authority/tooling gate");
    assert_eq!(cognition_gate.get("status").and_then(Value::as_str), Some("blocked"));
    assert_eq!(
        routing_model_gate.get("status").and_then(Value::as_str),
        Some("blocked")
    );
    assert_eq!(
        verification_output_gate
            .get("status")
            .and_then(Value::as_str),
        Some("blocked")
    );
    assert_eq!(
        authority_tooling_gate
            .get("status")
            .and_then(Value::as_str),
        Some("blocked")
    );
    assert!(
        cognition_gate
            .get("activationBlockers")
            .and_then(Value::as_array)
            .map(|blockers| blockers
                .iter()
                .any(|blocker| blocker.as_str() == Some("missing_attempt:prompt_assembler")))
            .unwrap_or(false)
    );
    assert!(
        cognition_gate
            .get("activationBlockers")
            .and_then(Value::as_array)
            .map(|blockers| blockers
                .iter()
                .any(|blocker| blocker.as_str() == Some("readiness_below_shadow:planner")))
            .unwrap_or(false)
    );
    assert!(
        routing_model_gate
            .get("activationBlockers")
            .and_then(Value::as_array)
            .map(|blockers| blockers
                .iter()
                .any(|blocker| blocker.as_str() == Some("missing_attempt:model_router")))
            .unwrap_or(false)
    );
    assert!(
        verification_output_gate
            .get("activationBlockers")
            .and_then(Value::as_array)
            .map(|blockers| blockers.iter().any(|blocker| {
                blocker.as_str() == Some("missing_attempt:postcondition_synthesizer")
            }))
            .unwrap_or(false)
    );
    assert!(
        authority_tooling_gate
            .get("activationBlockers")
            .and_then(Value::as_array)
            .map(|blockers| blockers
                .iter()
                .any(|blocker| blocker.as_str() == Some("missing_attempt:policy_gate")))
            .unwrap_or(false)
    );

    let loaded = load_workflow_run(bundle.workflow_path, result.summary.id)
        .expect("saved harness run should load");
    assert_eq!(loaded.harness_attempts.len(), 1);
    assert_eq!(loaded.harness_gated_cluster_runs.len(), 4);
    assert_eq!(
        loaded.node_runs[0]
            .harness_attempt
            .as_ref()
            .and_then(|attempt| attempt.get("replay"))
            .and_then(|replay| replay.get("determinism"))
            .and_then(Value::as_str),
        Some("deterministic")
    );
}
