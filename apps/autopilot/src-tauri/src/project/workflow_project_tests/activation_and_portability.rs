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
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "heavy-media-transform".to_string(),
        name: Some("Portable Media Transform".to_string()),
    })
    .expect("workflow should instantiate");
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
    let imported = import_workflow_package(ImportWorkflowPackageRequest {
        package_path: package.package_path,
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
}
