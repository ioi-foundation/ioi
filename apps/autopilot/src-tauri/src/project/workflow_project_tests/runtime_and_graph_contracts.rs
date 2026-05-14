#[test]
fn workflow_shared_executor_lifecycle_covers_successful_node_families() {
    let root = temp_root("shared-lifecycle");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Shared Lifecycle".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut source = workflow_node(
        "life-source",
        "source",
        "Manual input",
        80,
        180,
        "Input",
        "manual",
    );
    logic_mut(&mut source).insert("payload".to_string(), json!({"message": "lifecycle"}));
    let mut function = workflow_function_node(
        "life-function",
        "Normalize input",
        280,
        180,
        "return { approved: true, source: input };",
    );
    logic_mut(&mut function).insert(
        "functionBinding".to_string(),
        json!({
            "language": "javascript",
            "code": "return { approved: true, source: input };",
            "inputSchema": { "type": "object" },
            "outputSchema": { "type": "object", "required": ["approved"] },
            "sandboxPolicy": {
                "timeoutMs": 1000,
                "memoryMb": 64,
                "outputLimitBytes": 32768,
                "permissions": []
            },
            "testInput": { "message": "lifecycle" }
        }),
    );
    let assertion = workflow_node(
        "life-assertion",
        "test_assertion",
        "Assertion",
        480,
        180,
        "Assert",
        "present",
    );
    let adapter = workflow_node(
        "life-adapter",
        "adapter",
        "Connector read",
        680,
        180,
        "Connector",
        "mock.crm.read",
    );
    let mut decision = workflow_node(
        "life-decision",
        "decision",
        "Route result",
        880,
        180,
        "Decision",
        "left",
    );
    logic_mut(&mut decision).insert("defaultRoute".to_string(), json!("left"));
    let loop_node = workflow_node(
        "life-loop",
        "loop",
        "Loop guard",
        1080,
        180,
        "Loop",
        "bounded",
    );
    let barrier = workflow_node(
        "life-barrier",
        "barrier",
        "Join state",
        1280,
        180,
        "Barrier",
        "all",
    );
    let mut state = workflow_node(
        "life-state",
        "state",
        "Memory state",
        280,
        380,
        "State",
        "memory",
    );
    logic_mut(&mut state).insert("stateKey".to_string(), json!("lifecycle_memory"));
    logic_mut(&mut state).insert("stateOperation".to_string(), json!("merge"));
    let model_binding = workflow_node(
        "life-model-binding",
        "model_binding",
        "Reasoning model",
        1080,
        20,
        "Model",
        "reasoning",
    );
    let parser = workflow_node(
        "life-parser",
        "parser",
        "JSON parser",
        1080,
        360,
        "Parser",
        "schema",
    );
    let mut tool = workflow_node(
        "life-tool",
        "plugin_tool",
        "Search tool",
        680,
        380,
        "Tool",
        "mock.search",
    );
    logic_mut(&mut tool).insert(
        "toolBinding".to_string(),
        json!({
            "toolRef": "mock.search",
            "bindingKind": "plugin_tool",
            "mockBinding": true,
            "credentialReady": true,
            "capabilityScope": ["read"],
            "sideEffectClass": "read",
            "requiresApproval": false,
            "arguments": { "q": "lifecycle" },
            "argumentSchema": { "type": "object", "required": ["q"] },
            "resultSchema": { "type": "object", "required": ["toolRef", "arguments", "input"] }
        }),
    );
    let mut model = workflow_node(
        "life-model",
        "model_call",
        "Compose result",
        1480,
        180,
        "Model",
        "reasoning",
    );
    logic_mut(&mut model).insert(
        "outputSchema".to_string(),
        json!({"type": "object", "required": ["message", "attachments", "toolCalls"]}),
    );
    let mut subgraph = workflow_node(
        "life-subgraph",
        "subgraph",
        "Bound child workflow",
        1680,
        180,
        "Subgraph",
        "child",
    );
    logic_mut(&mut subgraph).insert(
        "subgraphRef".to_string(),
        json!({ "workflowPath": ".agents/workflows/child.workflow.json" }),
    );
    let mut proposal = workflow_node(
        "life-proposal",
        "proposal",
        "Bounded proposal",
        1880,
        180,
        "Proposal",
        "bounded",
    );
    logic_mut(&mut proposal).insert(
        "proposalAction".to_string(),
        json!({
            "actionKind": "create",
            "boundedTargets": ["workflow.nodes.life-model.config.logic.prompt"],
            "requiresApproval": true
        }),
    );
    let output = workflow_node(
        "life-output",
        "output",
        "Lifecycle output",
        2080,
        180,
        "Output",
        "markdown",
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![
        source,
        function,
        assertion,
        adapter,
        decision,
        loop_node,
        barrier,
        state,
        model_binding,
        parser,
        tool,
        model,
        subgraph,
        proposal,
        output,
    ];
    workflow.edges = vec![
        workflow_edge("edge-life-source-function", "life-source", "life-function"),
        workflow_edge("edge-life-source-state", "life-source", "life-state"),
        workflow_edge("edge-life-source-tool", "life-source", "life-tool"),
        workflow_edge(
            "edge-life-function-assertion",
            "life-function",
            "life-assertion",
        ),
        workflow_edge(
            "edge-life-assertion-adapter",
            "life-assertion",
            "life-adapter",
        ),
        workflow_edge(
            "edge-life-adapter-decision",
            "life-adapter",
            "life-decision",
        ),
        json!({
            "id": "edge-life-decision-loop",
            "from": "life-decision",
            "to": "life-loop",
            "fromPort": "left",
            "toPort": "input",
            "type": "data",
            "connectionClass": "data",
            "data": { "connectionClass": "data" }
        }),
        workflow_edge("edge-life-loop-barrier", "life-loop", "life-barrier"),
        workflow_edge("edge-life-state-barrier", "life-state", "life-barrier"),
        workflow_edge("edge-life-barrier-model", "life-barrier", "life-model"),
        json!({
            "id": "edge-life-model-binding-model",
            "from": "life-model-binding",
            "to": "life-model",
            "fromPort": "model",
            "toPort": "model",
            "type": "model",
            "connectionClass": "model",
            "data": { "connectionClass": "model" }
        }),
        json!({
            "id": "edge-life-parser-model",
            "from": "life-parser",
            "to": "life-model",
            "fromPort": "parser",
            "toPort": "parser",
            "type": "data",
            "connectionClass": "parser",
            "data": { "connectionClass": "parser" }
        }),
        json!({
            "id": "edge-life-tool-model",
            "from": "life-tool",
            "to": "life-model",
            "fromPort": "tool",
            "toPort": "tool",
            "type": "data",
            "connectionClass": "tool",
            "data": { "connectionClass": "tool" }
        }),
        json!({
            "id": "edge-life-state-model",
            "from": "life-state",
            "to": "life-model",
            "fromPort": "memory",
            "toPort": "memory",
            "type": "data",
            "connectionClass": "memory",
            "data": { "connectionClass": "memory" }
        }),
        workflow_edge("edge-life-model-subgraph", "life-model", "life-subgraph"),
        workflow_edge(
            "edge-life-subgraph-proposal",
            "life-subgraph",
            "life-proposal",
        ),
        workflow_edge("edge-life-proposal-output", "life-proposal", "life-output"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");
    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");

    let run = run_workflow_project(bundle.workflow_path, None).expect("workflow should run");
    assert_eq!(run.summary.status, "passed");
    let expected_node_ids = [
        "life-function",
        "life-assertion",
        "life-adapter",
        "life-decision",
        "life-loop",
        "life-barrier",
        "life-state",
        "life-model-binding",
        "life-parser",
        "life-tool",
        "life-model",
        "life-subgraph",
        "life-proposal",
        "life-output",
    ];
    for node_id in expected_node_ids {
        let node_run = run
            .node_runs
            .iter()
            .find(|candidate| candidate.node_id == node_id)
            .unwrap_or_else(|| panic!("{} should execute through shared lifecycle", node_id));
        assert_eq!(node_run.status, "success", "{} should succeed", node_id);
        for step in [
            "validate_config",
            "resolve_binding",
            "check_policy",
            "prepare_inputs",
            "execute_attempt",
            "validate_output",
            "record_run",
            "checkpoint",
            "emit_event",
            "evaluate_completion",
        ] {
            assert!(
                node_run.lifecycle.iter().any(|item| item == step),
                "{} should record lifecycle step {}",
                node_id,
                step
            );
        }
        assert!(
            node_run.checkpoint_id.is_some(),
            "{} should checkpoint",
            node_id
        );
        assert!(run.events.iter().any(|event| {
            event.kind == "node_started" && event.node_id.as_deref() == Some(node_id)
        }));
        assert!(run.events.iter().any(|event| {
            event.kind == "node_succeeded" && event.node_id.as_deref() == Some(node_id)
        }));
        assert!(run
            .verification_evidence
            .iter()
            .any(|evidence| { evidence.node_id == node_id && evidence.status == "passed" }));
    }
    assert!(!run
        .completion_requirements
        .iter()
        .any(|requirement| requirement.status != "satisfied"));
    assert!(run
        .events
        .iter()
        .any(|event| event.kind == "output_created"
            && event.node_id.as_deref() == Some("life-output")));
}

#[test]
fn workflow_package_export_and_import_nodes_execute_through_runtime() {
    let root = temp_root("package-node-runtime");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Package Node Runtime".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let source = workflow_node(
        "package-source",
        "source",
        "Package source",
        80,
        160,
        "Input",
        "manual",
    );
    let package_export = workflow_node(
        "package-export",
        "workflow_package_export",
        "Export package",
        300,
        160,
        "Package",
        "export",
    );
    let mut package_import = workflow_node(
        "package-import",
        "workflow_package_import",
        "Import package",
        540,
        160,
        "Package",
        "import",
    );
    logic_mut(&mut package_import).insert(
        "workflowPackageImportName".to_string(),
        json!("Package Node Runtime Imported"),
    );
    let output = workflow_node(
        "package-output",
        "output",
        "Package output",
        780,
        160,
        "Output",
        "summary",
    );

    let mut workflow = bundle.workflow.clone();
    workflow.global_config["workflowChromeLocale"] = json!("es-ES");
    workflow.nodes = vec![source, package_export, package_import, output];
    workflow.edges = vec![
        workflow_edge(
            "edge-package-source-export",
            "package-source",
            "package-export",
        ),
        workflow_edge_ports(
            "edge-package-export-import",
            "package-export",
            "package-import",
            "package",
            "package",
        ),
        workflow_edge(
            "edge-package-import-output",
            "package-import",
            "package-output",
        ),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");

    let run = run_workflow_project(bundle.workflow_path, None).expect("workflow should run");
    assert_eq!(run.summary.status, "passed");
    let export_run = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "package-export")
        .expect("package export should run");
    assert_eq!(export_run.status, "success");
    let export_output = export_run.output.as_ref().expect("export output");
    assert_eq!(
        export_output.get("toolName").and_then(Value::as_str),
        Some("workflow.package.export")
    );
    assert_eq!(
        export_output
            .get("workflowChromeLocale")
            .and_then(Value::as_str),
        Some("es-ES")
    );
    assert!(export_output
        .get("packagePath")
        .and_then(Value::as_str)
        .map(|path| path.ends_with(".portable"))
        .unwrap_or(false));

    let import_run = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "package-import")
        .expect("package import should run");
    assert_eq!(import_run.status, "success");
    let import_output = import_run.output.as_ref().expect("import output");
    assert_eq!(
        import_output.get("toolName").and_then(Value::as_str),
        Some("workflow.package.import")
    );
    assert_eq!(
        import_output
            .get("workflowChromeLocalePreserved")
            .and_then(Value::as_bool),
        Some(true)
    );
    assert!(import_output
        .get("importedWorkflowPath")
        .and_then(Value::as_str)
        .map(|path| path.ends_with("package-node-runtime-imported.workflow.json"))
        .unwrap_or(false));
    assert!(run.verification_evidence.iter().any(|evidence| {
        evidence.node_id == "package-export"
            && evidence.evidence_type == "workflow_package_export"
            && evidence.status == "passed"
    }));
    assert!(run.verification_evidence.iter().any(|evidence| {
        evidence.node_id == "package-import"
            && evidence.evidence_type == "workflow_package_import"
            && evidence.status == "passed"
    }));
}

#[test]
fn runtime_thread_fork_node_builds_react_flow_control_request() {
    let root = temp_root("runtime-thread-fork");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Runtime Thread Fork".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut fork = workflow_node(
        "fork-control",
        "runtime_thread_fork",
        "Fork control",
        120,
        180,
        "Fork",
        "control",
    );
    logic_mut(&mut fork).insert(
        "runtimeThreadForkEndpoint".to_string(),
        json!("/v1/threads/{threadId}/fork"),
    );
    logic_mut(&mut fork).insert(
        "runtimeThreadForkThreadIdField".to_string(),
        json!("threadId"),
    );
    logic_mut(&mut fork).insert("runtimeThreadForkReasonField".to_string(), json!("reason"));
    logic_mut(&mut fork).insert(
        "runtimeThreadForkWorkflowNodeId".to_string(),
        json!("runtime.thread-fork"),
    );
    logic_mut(&mut fork).insert("runtimeThreadForkActor".to_string(), json!("operator"));
    logic_mut(&mut fork).insert(
        "outputSchema".to_string(),
        workflow_runtime_thread_fork_output_schema(),
    );

    let mut workflow = bundle.workflow.clone();
    let workflow_graph_id = workflow.metadata.id.clone();
    workflow.nodes = vec![fork];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");

    let run = run_workflow_node(
        bundle.workflow_path,
        "fork-control".to_string(),
        Some(json!({
            "threadId": "thread_react_flow",
            "reason": "branch from React Flow runtime control"
        })),
        None,
    )
    .expect("runtime thread fork node should run");
    assert_eq!(run.summary.status, "passed");
    let node_run = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "fork-control")
        .expect("fork node should run");
    let output = node_run.output.as_ref().expect("fork output should exist");
    assert_eq!(
        output.get("kind").and_then(Value::as_str),
        Some("runtime_thread_fork")
    );
    assert_eq!(
        output.get("source").and_then(Value::as_str),
        Some("react_flow")
    );
    assert_eq!(
        output.get("componentKind").and_then(Value::as_str),
        Some("thread_fork")
    );
    assert_eq!(
        output.get("workflowGraphId").and_then(Value::as_str),
        Some(workflow_graph_id.as_str())
    );
    assert_eq!(
        output.get("workflowNodeId").and_then(Value::as_str),
        Some("runtime.thread-fork")
    );
    assert_eq!(
        output.get("threadId").and_then(Value::as_str),
        Some("thread_react_flow")
    );
    assert_eq!(
        output.get("endpoint").and_then(Value::as_str),
        Some("/v1/threads/thread_react_flow/fork")
    );
    let request = output.get("request").expect("fork request should exist");
    assert_eq!(
        request.get("source").and_then(Value::as_str),
        Some("react_flow")
    );
    assert_eq!(
        request.get("workflowGraphId").and_then(Value::as_str),
        Some(workflow_graph_id.as_str())
    );
    assert_eq!(
        request.get("workflowNodeId").and_then(Value::as_str),
        Some("runtime.thread-fork")
    );
    assert_eq!(
        request.get("eventKind").and_then(Value::as_str),
        Some("OperatorControl.Fork")
    );
}

#[test]
fn runtime_operator_interrupt_node_builds_react_flow_control_request() {
    let root = temp_root("runtime-operator-interrupt");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Runtime Operator Interrupt".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut interrupt = workflow_node(
        "interrupt-control",
        "runtime_operator_interrupt",
        "Interrupt control",
        120,
        180,
        "Interrupt",
        "control",
    );
    logic_mut(&mut interrupt).insert(
        "runtimeOperatorInterruptEndpoint".to_string(),
        json!("/v1/threads/{threadId}/turns/{turnId}/interrupt"),
    );
    logic_mut(&mut interrupt).insert(
        "runtimeOperatorInterruptThreadIdField".to_string(),
        json!("threadId"),
    );
    logic_mut(&mut interrupt).insert(
        "runtimeOperatorInterruptTurnIdField".to_string(),
        json!("turnId"),
    );
    logic_mut(&mut interrupt).insert(
        "runtimeOperatorInterruptReasonField".to_string(),
        json!("reason"),
    );
    logic_mut(&mut interrupt).insert(
        "runtimeOperatorInterruptWorkflowNodeId".to_string(),
        json!("runtime.operator-interrupt"),
    );
    logic_mut(&mut interrupt).insert(
        "runtimeOperatorInterruptActor".to_string(),
        json!("operator"),
    );
    logic_mut(&mut interrupt).insert(
        "outputSchema".to_string(),
        workflow_runtime_operator_interrupt_output_schema(),
    );

    let mut workflow = bundle.workflow.clone();
    let workflow_graph_id = workflow.metadata.id.clone();
    workflow.nodes = vec![interrupt];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");

    let run = run_workflow_node(
        bundle.workflow_path,
        "interrupt-control".to_string(),
        Some(json!({
            "threadId": "thread_react_flow",
            "turnId": "turn_react_flow",
            "reason": "pause from React Flow runtime control"
        })),
        None,
    )
    .expect("runtime operator interrupt node should run");
    assert_eq!(run.summary.status, "passed");
    let node_run = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "interrupt-control")
        .expect("interrupt node should run");
    let output = node_run
        .output
        .as_ref()
        .expect("interrupt output should exist");
    assert_eq!(
        output.get("kind").and_then(Value::as_str),
        Some("runtime_operator_interrupt")
    );
    assert_eq!(
        output.get("source").and_then(Value::as_str),
        Some("react_flow")
    );
    assert_eq!(
        output.get("componentKind").and_then(Value::as_str),
        Some("operator_control")
    );
    assert_eq!(
        output.get("workflowGraphId").and_then(Value::as_str),
        Some(workflow_graph_id.as_str())
    );
    assert_eq!(
        output.get("workflowNodeId").and_then(Value::as_str),
        Some("runtime.operator-interrupt")
    );
    assert_eq!(
        output.get("threadId").and_then(Value::as_str),
        Some("thread_react_flow")
    );
    assert_eq!(
        output.get("turnId").and_then(Value::as_str),
        Some("turn_react_flow")
    );
    assert_eq!(
        output.get("endpoint").and_then(Value::as_str),
        Some("/v1/threads/thread_react_flow/turns/turn_react_flow/interrupt")
    );
    let request = output
        .get("request")
        .expect("interrupt request should exist");
    assert_eq!(
        request.get("source").and_then(Value::as_str),
        Some("react_flow")
    );
    assert_eq!(
        request.get("workflowGraphId").and_then(Value::as_str),
        Some(workflow_graph_id.as_str())
    );
    assert_eq!(
        request.get("workflowNodeId").and_then(Value::as_str),
        Some("runtime.operator-interrupt")
    );
    assert_eq!(
        request.get("eventKind").and_then(Value::as_str),
        Some("OperatorControl.Interrupt")
    );
}

#[test]
fn runtime_operator_steer_node_builds_react_flow_control_request() {
    let root = temp_root("runtime-operator-steer");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Runtime Operator Steer".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut steer = workflow_node(
        "steer-control",
        "runtime_operator_steer",
        "Steer control",
        120,
        180,
        "Steer",
        "control",
    );
    logic_mut(&mut steer).insert(
        "runtimeOperatorSteerEndpoint".to_string(),
        json!("/v1/threads/{threadId}/turns/{turnId}/steer"),
    );
    logic_mut(&mut steer).insert(
        "runtimeOperatorSteerThreadIdField".to_string(),
        json!("threadId"),
    );
    logic_mut(&mut steer).insert(
        "runtimeOperatorSteerTurnIdField".to_string(),
        json!("turnId"),
    );
    logic_mut(&mut steer).insert(
        "runtimeOperatorSteerGuidanceField".to_string(),
        json!("guidance"),
    );
    logic_mut(&mut steer).insert(
        "runtimeOperatorSteerWorkflowNodeId".to_string(),
        json!("runtime.operator-steer"),
    );
    logic_mut(&mut steer).insert("runtimeOperatorSteerActor".to_string(), json!("operator"));
    logic_mut(&mut steer).insert(
        "outputSchema".to_string(),
        workflow_runtime_operator_steer_output_schema(),
    );

    let mut workflow = bundle.workflow.clone();
    let workflow_graph_id = workflow.metadata.id.clone();
    workflow.nodes = vec![steer];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");

    let run = run_workflow_node(
        bundle.workflow_path,
        "steer-control".to_string(),
        Some(json!({
            "threadId": "thread_react_flow",
            "turnId": "turn_react_flow",
            "guidance": "focus from React Flow runtime control"
        })),
        None,
    )
    .expect("runtime operator steer node should run");
    assert_eq!(run.summary.status, "passed");
    let node_run = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "steer-control")
        .expect("steer node should run");
    let output = node_run.output.as_ref().expect("steer output should exist");
    assert_eq!(
        output.get("kind").and_then(Value::as_str),
        Some("runtime_operator_steer")
    );
    assert_eq!(
        output.get("source").and_then(Value::as_str),
        Some("react_flow")
    );
    assert_eq!(
        output.get("componentKind").and_then(Value::as_str),
        Some("operator_control")
    );
    assert_eq!(
        output.get("workflowGraphId").and_then(Value::as_str),
        Some(workflow_graph_id.as_str())
    );
    assert_eq!(
        output.get("workflowNodeId").and_then(Value::as_str),
        Some("runtime.operator-steer")
    );
    assert_eq!(
        output.get("threadId").and_then(Value::as_str),
        Some("thread_react_flow")
    );
    assert_eq!(
        output.get("turnId").and_then(Value::as_str),
        Some("turn_react_flow")
    );
    assert_eq!(
        output.get("endpoint").and_then(Value::as_str),
        Some("/v1/threads/thread_react_flow/turns/turn_react_flow/steer")
    );
    let request = output.get("request").expect("steer request should exist");
    assert_eq!(
        request.get("source").and_then(Value::as_str),
        Some("react_flow")
    );
    assert_eq!(
        request.get("workflowGraphId").and_then(Value::as_str),
        Some(workflow_graph_id.as_str())
    );
    assert_eq!(
        request.get("workflowNodeId").and_then(Value::as_str),
        Some("runtime.operator-steer")
    );
    assert_eq!(
        request.get("eventKind").and_then(Value::as_str),
        Some("OperatorControl.Steer")
    );
    assert_eq!(
        request.get("guidance").and_then(Value::as_str),
        Some("focus from React Flow runtime control")
    );
}

#[test]
fn runtime_thread_mode_node_builds_react_flow_control_request() {
    let root = temp_root("runtime-thread-mode");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Runtime Thread Mode".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut mode = workflow_node(
        "mode-control",
        "runtime_thread_mode",
        "Mode control",
        120,
        180,
        "Mode",
        "control",
    );
    logic_mut(&mut mode).insert(
        "runtimeThreadModeEndpoint".to_string(),
        json!("/v1/threads/{threadId}/mode"),
    );
    logic_mut(&mut mode).insert(
        "runtimeThreadModeThreadIdField".to_string(),
        json!("threadId"),
    );
    logic_mut(&mut mode).insert("runtimeThreadModeModeField".to_string(), json!("mode"));
    logic_mut(&mut mode).insert(
        "runtimeThreadModeApprovalModeField".to_string(),
        json!("approvalMode"),
    );
    logic_mut(&mut mode).insert(
        "runtimeThreadModeTrustProfileField".to_string(),
        json!("trustProfile"),
    );
    logic_mut(&mut mode).insert(
        "runtimeThreadModeWorkspaceTrustWorkflowNodeId".to_string(),
        json!("runtime.thread-mode.workspace-trust"),
    );
    logic_mut(&mut mode).insert(
        "runtimeThreadModeWorkflowNodeId".to_string(),
        json!("runtime.thread-mode"),
    );
    logic_mut(&mut mode).insert("runtimeThreadModeActor".to_string(), json!("operator"));
    logic_mut(&mut mode).insert(
        "outputSchema".to_string(),
        workflow_runtime_thread_mode_output_schema(),
    );

    let mut workflow = bundle.workflow.clone();
    let workflow_graph_id = workflow.metadata.id.clone();
    workflow.nodes = vec![mode];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");

    let run = run_workflow_node(
        bundle.workflow_path,
        "mode-control".to_string(),
        Some(json!({
            "threadId": "thread_react_flow",
            "mode": "yolo",
            "approvalMode": "never_prompt",
            "trustProfile": "canvas_claimed_trusted"
        })),
        None,
    )
    .expect("runtime thread mode node should run");
    assert_eq!(run.summary.status, "passed");
    let node_run = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "mode-control")
        .expect("mode node should run");
    let output = node_run.output.as_ref().expect("mode output should exist");
    assert_eq!(
        output.get("kind").and_then(Value::as_str),
        Some("runtime_thread_mode")
    );
    assert_eq!(output.get("source").and_then(Value::as_str), Some("react_flow"));
    assert_eq!(
        output.get("componentKind").and_then(Value::as_str),
        Some("runtime_mode")
    );
    assert_eq!(
        output.get("workflowGraphId").and_then(Value::as_str),
        Some(workflow_graph_id.as_str())
    );
    assert_eq!(
        output.get("workflowNodeId").and_then(Value::as_str),
        Some("runtime.thread-mode")
    );
    assert_eq!(
        output.get("endpoint").and_then(Value::as_str),
        Some("/v1/threads/thread_react_flow/mode")
    );
    assert_eq!(output.get("mode").and_then(Value::as_str), Some("yolo"));
    assert_eq!(
        output.get("approvalMode").and_then(Value::as_str),
        Some("never_prompt")
    );
    let request = output.get("request").expect("mode request should exist");
    assert_eq!(request.get("mode").and_then(Value::as_str), Some("yolo"));
    assert_eq!(
        request.get("approval_mode").and_then(Value::as_str),
        Some("never_prompt")
    );
    assert_eq!(
        request.get("trust_profile").and_then(Value::as_str),
        Some("canvas_claimed_trusted")
    );
    assert_eq!(
        request
            .get("workspace_trust_workflow_node_id")
            .and_then(Value::as_str),
        Some("runtime.thread-mode.workspace-trust")
    );
    assert_eq!(
        request.get("eventKind").and_then(Value::as_str),
        Some("OperatorControl.Mode")
    );
}

#[test]
fn runtime_context_compact_node_builds_react_flow_control_request() {
    let root = temp_root("runtime-context-compact");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Runtime Context Compact".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut compact = workflow_node(
        "compact-control",
        "runtime_context_compact",
        "Compact control",
        120,
        180,
        "Compact",
        "control",
    );
    logic_mut(&mut compact).insert(
        "runtimeContextCompactEndpoint".to_string(),
        json!("/v1/threads/{threadId}/compact"),
    );
    logic_mut(&mut compact).insert(
        "runtimeContextCompactThreadIdField".to_string(),
        json!("threadId"),
    );
    logic_mut(&mut compact).insert(
        "runtimeContextCompactTurnIdField".to_string(),
        json!("turnId"),
    );
    logic_mut(&mut compact).insert(
        "runtimeContextCompactReasonField".to_string(),
        json!("reason"),
    );
    logic_mut(&mut compact).insert(
        "runtimeContextCompactScopeField".to_string(),
        json!("scope"),
    );
    logic_mut(&mut compact).insert(
        "runtimeContextCompactWorkflowNodeId".to_string(),
        json!("runtime.context-compact"),
    );
    logic_mut(&mut compact).insert("runtimeContextCompactActor".to_string(), json!("operator"));
    logic_mut(&mut compact).insert(
        "outputSchema".to_string(),
        workflow_runtime_context_compact_output_schema(),
    );

    let mut workflow = bundle.workflow.clone();
    let workflow_graph_id = workflow.metadata.id.clone();
    workflow.nodes = vec![compact];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");

    let run = run_workflow_node(
        bundle.workflow_path,
        "compact-control".to_string(),
        Some(json!({
            "threadId": "thread_react_flow",
            "turnId": "turn_react_flow",
            "reason": "compact from React Flow runtime control",
            "scope": "thread"
        })),
        None,
    )
    .expect("runtime context compact node should run");
    assert_eq!(run.summary.status, "passed");
    let node_run = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "compact-control")
        .expect("compact node should run");
    let output = node_run
        .output
        .as_ref()
        .expect("compact output should exist");
    assert_eq!(
        output.get("kind").and_then(Value::as_str),
        Some("runtime_context_compact")
    );
    assert_eq!(
        output.get("source").and_then(Value::as_str),
        Some("react_flow")
    );
    assert_eq!(
        output.get("componentKind").and_then(Value::as_str),
        Some("context_compaction")
    );
    assert_eq!(
        output.get("workflowGraphId").and_then(Value::as_str),
        Some(workflow_graph_id.as_str())
    );
    assert_eq!(
        output.get("workflowNodeId").and_then(Value::as_str),
        Some("runtime.context-compact")
    );
    assert_eq!(
        output.get("threadId").and_then(Value::as_str),
        Some("thread_react_flow")
    );
    assert_eq!(
        output.get("turnId").and_then(Value::as_str),
        Some("turn_react_flow")
    );
    assert_eq!(
        output.get("endpoint").and_then(Value::as_str),
        Some("/v1/threads/thread_react_flow/compact")
    );
    let request = output.get("request").expect("compact request should exist");
    assert_eq!(
        request.get("source").and_then(Value::as_str),
        Some("react_flow")
    );
    assert_eq!(
        request.get("workflowGraphId").and_then(Value::as_str),
        Some(workflow_graph_id.as_str())
    );
    assert_eq!(
        request.get("workflowNodeId").and_then(Value::as_str),
        Some("runtime.context-compact")
    );
    assert_eq!(
        request.get("eventKind").and_then(Value::as_str),
        Some("OperatorControl.Compact")
    );
    assert_eq!(
        request.get("reason").and_then(Value::as_str),
        Some("compact from React Flow runtime control")
    );
    assert_eq!(request.get("scope").and_then(Value::as_str), Some("thread"));
}

#[test]
fn github_pr_create_dry_run_node_executes_through_runtime() {
    let root = temp_root("github-pr-create-runtime");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "GitHub PR Create Runtime".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut repository = workflow_node(
        "repository-context",
        "repository_context",
        "Repository context",
        80,
        180,
        "Repo",
        "context",
    );
    logic_mut(&mut repository).insert("repoFullName".to_string(), json!("ioi-test/ioi"));
    logic_mut(&mut repository).insert("branch".to_string(), json!("feature/runtime-pr-plan"));
    logic_mut(&mut repository).insert("defaultBranch".to_string(), json!("main"));
    logic_mut(&mut repository).insert("dirty".to_string(), json!(false));

    let mut branch_policy = workflow_node(
        "branch-policy",
        "branch_policy",
        "Branch policy",
        320,
        180,
        "Policy",
        "passed",
    );
    logic_mut(&mut branch_policy).insert("allowDirtyWorktree".to_string(), json!(true));
    logic_mut(&mut branch_policy).insert("blockProtectedBranches".to_string(), json!(false));

    let mut github_context = workflow_node(
        "github-context",
        "github_context",
        "GitHub context",
        560,
        180,
        "GitHub",
        "available",
    );
    logic_mut(&mut github_context).insert("repoFullName".to_string(), json!("ioi-test/ioi"));
    logic_mut(&mut github_context).insert("tokenAvailable".to_string(), json!(false));

    let issue_context = workflow_node(
        "issue-context",
        "issue_context",
        "Issue context",
        800,
        180,
        "Issue",
        "unbound",
    );

    let mut pr_attempt = workflow_node(
        "pr-attempt",
        "pr_attempt",
        "PR attempt",
        1040,
        180,
        "PR",
        "ready",
    );
    logic_mut(&mut pr_attempt).insert("title".to_string(), json!("Runtime dry-run PR plan"));
    logic_mut(&mut pr_attempt).insert("baseBranch".to_string(), json!("main"));
    logic_mut(&mut pr_attempt).insert("headBranch".to_string(), json!("feature/runtime-pr-plan"));
    logic_mut(&mut pr_attempt).insert("diffArtifactAttached".to_string(), json!(true));
    logic_mut(&mut pr_attempt).insert("branchArtifactAttached".to_string(), json!(true));

    let mut review_gate = workflow_node(
        "review-gate",
        "review_gate",
        "Review gate",
        1280,
        180,
        "Review",
        "blocked",
    );
    logic_mut(&mut review_gate).insert("reviewSatisfied".to_string(), json!(false));

    let github_pr_create = workflow_node(
        "github-pr-create",
        "github_pr_create",
        "GitHub PR create",
        1520,
        180,
        "Tool",
        "dry-run",
    );
    let output = workflow_node(
        "pr-output",
        "output",
        "PR plan output",
        1760,
        180,
        "Output",
        "summary",
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![
        repository,
        branch_policy,
        github_context,
        issue_context,
        pr_attempt,
        review_gate,
        github_pr_create,
        output,
    ];
    workflow.edges = vec![
        workflow_edge_ports(
            "edge-repository-branch-policy",
            "repository-context",
            "branch-policy",
            "repository",
            "repository",
        ),
        workflow_edge_ports(
            "edge-repository-github-context",
            "repository-context",
            "github-context",
            "repository",
            "repository",
        ),
        workflow_edge_ports(
            "edge-branch-policy-github-context",
            "branch-policy",
            "github-context",
            "branch_policy",
            "branch_policy",
        ),
        workflow_edge_ports(
            "edge-github-context-issue-context",
            "github-context",
            "issue-context",
            "github_context",
            "github_context",
        ),
        workflow_edge_ports(
            "edge-repository-pr-attempt",
            "repository-context",
            "pr-attempt",
            "repository",
            "repository",
        ),
        workflow_edge_ports(
            "edge-branch-policy-pr-attempt",
            "branch-policy",
            "pr-attempt",
            "branch_policy",
            "branch_policy",
        ),
        workflow_edge_ports(
            "edge-github-context-pr-attempt",
            "github-context",
            "pr-attempt",
            "github_context",
            "github_context",
        ),
        workflow_edge_ports(
            "edge-issue-context-pr-attempt",
            "issue-context",
            "pr-attempt",
            "issue_context",
            "issue_context",
        ),
        workflow_edge_ports(
            "edge-repository-review-gate",
            "repository-context",
            "review-gate",
            "repository",
            "repository",
        ),
        workflow_edge_ports(
            "edge-branch-policy-review-gate",
            "branch-policy",
            "review-gate",
            "branch_policy",
            "branch_policy",
        ),
        workflow_edge_ports(
            "edge-github-context-review-gate",
            "github-context",
            "review-gate",
            "github_context",
            "github_context",
        ),
        workflow_edge_ports(
            "edge-issue-context-review-gate",
            "issue-context",
            "review-gate",
            "issue_context",
            "issue_context",
        ),
        workflow_edge_ports(
            "edge-pr-attempt-review-gate",
            "pr-attempt",
            "review-gate",
            "pr_attempt",
            "pr_attempt",
        ),
        workflow_edge_ports(
            "edge-repository-github-pr-create",
            "repository-context",
            "github-pr-create",
            "repository",
            "repository",
        ),
        workflow_edge_ports(
            "edge-branch-policy-github-pr-create",
            "branch-policy",
            "github-pr-create",
            "branch_policy",
            "branch_policy",
        ),
        workflow_edge_ports(
            "edge-github-context-github-pr-create",
            "github-context",
            "github-pr-create",
            "github_context",
            "github_context",
        ),
        workflow_edge_ports(
            "edge-issue-context-github-pr-create",
            "issue-context",
            "github-pr-create",
            "issue_context",
            "issue_context",
        ),
        workflow_edge_ports(
            "edge-pr-attempt-github-pr-create",
            "pr-attempt",
            "github-pr-create",
            "pr_attempt",
            "pr_attempt",
        ),
        workflow_edge_ports(
            "edge-review-gate-github-pr-create",
            "review-gate",
            "github-pr-create",
            "review_gate",
            "review_gate",
        ),
        workflow_edge_ports(
            "edge-github-pr-create-output",
            "github-pr-create",
            "pr-output",
            "request",
            "input",
        ),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");

    let run = run_workflow_project(bundle.workflow_path, None).expect("workflow should run");
    assert_eq!(run.summary.status, "passed");
    let pr_create_run = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "github-pr-create")
        .expect("github_pr_create should run");
    assert_eq!(pr_create_run.status, "success");
    let plan = pr_create_run
        .output
        .as_ref()
        .expect("github_pr_create output");
    assert_eq!(
        plan.get("schemaVersion").and_then(Value::as_str),
        Some("ioi.agent-runtime.github-pr-create-plan.v1")
    );
    assert_eq!(
        plan.get("object").and_then(Value::as_str),
        Some("ioi.github_pr_create_plan")
    );
    assert_eq!(plan.get("status").and_then(Value::as_str), Some("blocked"));
    assert_eq!(
        plan.get("decision").and_then(Value::as_str),
        Some("blocked")
    );
    assert_eq!(plan.get("dryRun").and_then(Value::as_bool), Some(true));
    assert_eq!(plan.get("previewOnly").and_then(Value::as_bool), Some(true));
    assert_eq!(
        plan.get("toolName").and_then(Value::as_str),
        Some("github__pr_create")
    );
    assert_eq!(
        plan.get("action").and_then(Value::as_str),
        Some("pr_create")
    );
    assert_eq!(
        plan.get("repoFullName").and_then(Value::as_str),
        Some("ioi-test/ioi")
    );
    assert_eq!(
        plan.get("request")
            .and_then(|request| request.get("method"))
            .and_then(Value::as_str),
        Some("POST")
    );
    assert_eq!(
        plan.get("request")
            .and_then(|request| request.get("path"))
            .and_then(Value::as_str),
        Some("/repos/ioi-test/ioi/pulls")
    );
    let payload_hash = plan
        .get("request")
        .and_then(|request| request.get("payloadHash"))
        .and_then(Value::as_str)
        .expect("request payload hash");
    assert_eq!(payload_hash.len(), 64);
    assert!(payload_hash
        .chars()
        .all(|unit| unit.is_ascii_hexdigit() && !unit.is_ascii_uppercase()));
    assert_eq!(
        plan.get("request")
            .and_then(|request| request.get("bodyIncluded"))
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        plan.get("request")
            .and_then(|request| request.get("tokenIncluded"))
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        plan.get("authority")
            .and_then(|authority| authority.get("scopeGranted"))
            .and_then(Value::as_bool),
        Some(false)
    );
    let blockers = plan
        .get("blockers")
        .and_then(Value::as_array)
        .expect("blockers");
    for expected in [
        "review_gate_not_passed",
        "review_not_satisfied",
        "missing_authority_scope:github.pr.create",
        "dry_run_only",
    ] {
        assert!(blockers
            .iter()
            .any(|blocker| blocker.as_str() == Some(expected)));
    }
    assert_eq!(
        plan.get("networkLookupPerformed").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        plan.get("mutationAttempted").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        plan.get("mutationExecuted").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        plan.get("redaction")
            .and_then(|redaction| redaction.get("tokenValueIncluded"))
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        plan.get("redaction")
            .and_then(|redaction| redaction.get("requestBodyIncluded"))
            .and_then(Value::as_bool),
        Some(false)
    );
    let serialized_plan = serde_json::to_string(plan).expect("serialize plan");
    assert!(!serialized_plan.contains("Bearer "));
    assert!(!serialized_plan.contains("Authorization:"));
    assert!(run.verification_evidence.iter().any(|evidence| {
        evidence.node_id == "github-pr-create"
            && evidence.evidence_type == "github_pr_create"
            && evidence.status == "passed"
    }));
}

#[test]
fn workflow_skill_context_discovery_attaches_model_context() {
    let root = temp_root("skill-context-discovery");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Skill Context Discovery".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut source = workflow_node("skill-source", "source", "Goal", 80, 160, "Input", "manual");
    logic_mut(&mut source).insert(
        "payload".to_string(),
        json!({"request": "Build a frontend app user interface with polished workflow controls."}),
    );
    let skill_context = workflow_node(
        "skill-context",
        "skill_context",
        "Runtime skills",
        320,
        260,
        "Skills",
        "discover",
    );
    let mut model = workflow_node(
        "skill-model",
        "model_call",
        "Plan with skills",
        560,
        160,
        "Model",
        "reasoning",
    );
    logic_mut(&mut model).insert(
        "outputSchema".to_string(),
        json!({"type": "object", "required": ["message", "attachments"]}),
    );
    let output = workflow_node(
        "skill-output",
        "output",
        "Output",
        820,
        160,
        "Output",
        "markdown",
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, skill_context, model, output];
    workflow.edges = vec![
        workflow_edge("edge-source-skill", "skill-source", "skill-context"),
        workflow_edge("edge-source-model", "skill-source", "skill-model"),
        json!({
            "id": "edge-skill-model-context",
            "from": "skill-context",
            "to": "skill-model",
            "fromPort": "output",
            "toPort": "context",
            "type": "data",
            "connectionClass": "data",
            "data": { "connectionClass": "data" }
        }),
        workflow_edge("edge-model-output", "skill-model", "skill-output"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");
    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");

    let run = run_workflow_project(
        bundle.workflow_path,
        Some(json!({
            "skillCatalog": [{
                "skillHash": "skill-frontend",
                "name": "frontend-skill",
                "description": "Frontend app user interface design and workflow controls.",
                "lifecycleState": "promoted",
                "sourceType": "runtime_registry",
                "successRateBps": 9300,
                "sampleSize": 42,
                "relativePath": "skills/frontend/SKILL.md",
                "stale": false,
                "markdown": "# frontend-skill\nUse visual hierarchy, stable controls, and domain-specific UI composition."
            }]
        })),
    )
    .expect("workflow should run");
    assert_eq!(run.summary.status, "passed");
    let skill_run = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "skill-context")
        .expect("skill context should run");
    let skill_output = skill_run.output.as_ref().expect("skill output");
    assert_eq!(
        skill_output.get("schemaVersion").and_then(Value::as_str),
        Some("workflow.skill-context.v1")
    );
    assert_eq!(
        skill_output.get("status").and_then(Value::as_str),
        Some("attached")
    );
    assert!(skill_output
        .get("evidenceRefs")
        .and_then(Value::as_array)
        .expect("evidence refs")
        .iter()
        .any(|item| item.as_str() == Some("workflow.skill_context.discovery.v1:skill-context")));
    assert!(skill_output
        .get("evidenceRefs")
        .and_then(Value::as_array)
        .expect("evidence refs")
        .iter()
        .any(|item| item.as_str() == Some("workflow.skill_context.read.v1:skill-frontend")));
    let model_run = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "skill-model")
        .expect("model should run");
    let model_skill_context = model_run
        .output
        .as_ref()
        .and_then(|output| output.get("attachments"))
        .and_then(|attachments| attachments.get("skillContext"))
        .expect("model should receive skill context attachment");
    assert_eq!(
        model_skill_context
            .get("selectedSkills")
            .and_then(Value::as_array)
            .and_then(|items| items.first())
            .and_then(|item| item.get("skillHash"))
            .and_then(Value::as_str),
        Some("skill-frontend")
    );
    assert!(run.verification_evidence.iter().any(|evidence| {
        evidence.node_id == "skill-context"
            && evidence.evidence_type == "skill_context"
            && evidence.summary.contains("skill-frontend")
    }));
    assert!(run.route_evidence.iter().any(|evidence| {
        evidence.evidence_kind == "coding.route.skill_selection.v1"
            && evidence
                .selected_skill_hashes
                .iter()
                .any(|hash| hash == "skill-frontend")
    }));
}

#[test]
fn coding_route_templates_validate_run_and_emit_route_evidence() {
    let route_skill_catalog = json!({
        "skillCatalog": [
            {
                "skillHash": "skill-incremental",
                "name": "incremental-implementation",
                "description": "Incremental implementation with focused verification.",
                "lifecycleState": "promoted",
                "sourceType": "runtime_registry",
                "successRateBps": 9400,
                "sampleSize": 48,
                "relativePath": "skills/incremental/SKILL.md",
                "stale": false,
                "markdown": "Use narrow slices, focused edits, and verification evidence."
            },
            {
                "skillHash": "skill-debug",
                "name": "debugging",
                "description": "Reproduce failures and verify fixes.",
                "lifecycleState": "validated",
                "sourceType": "runtime_registry",
                "successRateBps": 9100,
                "sampleSize": 32,
                "relativePath": "skills/debugging/SKILL.md",
                "stale": false,
                "markdown": "Capture repro evidence, isolate the cause, and verify the fix."
            },
            {
                "skillHash": "skill-review",
                "name": "code-review",
                "description": "Review code for bugs, risks, and missing tests.",
                "lifecycleState": "promoted",
                "sourceType": "runtime_registry",
                "successRateBps": 9200,
                "sampleSize": 36,
                "relativePath": "skills/review/SKILL.md",
                "stale": false,
                "markdown": "Lead with findings and cite evidence."
            }
        ]
    });
    for (template_id, expected_skill_hash) in [
        ("coding.template.build", "skill-incremental"),
        ("coding.template.debug", "skill-debug"),
        ("coding.template.review", "skill-review"),
    ] {
        let root = temp_root(&format!("route-template-{}", template_id.replace('.', "-")));
        let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
            project_root: root.display().to_string(),
            template_id: template_id.to_string(),
            name: Some(format!("{} proof", template_id)),
        })
        .expect("route template should create");
        assert_eq!(
            bundle
                .workflow
                .global_config
                .get("codingRoute")
                .and_then(|route| route.get("routeId"))
                .and_then(Value::as_str),
            Some(template_id)
        );
        assert!(bundle.workflow.nodes.iter().any(|node| {
            workflow_node_id(node).as_deref() == Some("skill-context-route")
                && workflow_node_type(node) == "skill_context"
        }));
        assert!(bundle.workflow.edges.iter().any(|edge| {
            workflow_edge_from(edge).as_deref() == Some("skill-context-route")
                && workflow_edge_to(edge).as_deref() == Some("model-route-worker")
                && workflow_edge_to_port(edge) == "context"
        }));
        let validation =
            validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
        assert_eq!(validation.status, "passed", "{template_id} should validate");

        let run = run_workflow_project(bundle.workflow_path, Some(route_skill_catalog.clone()))
            .expect("route template should run");
        assert_eq!(run.summary.status, "passed", "{template_id} should pass");
        assert!(run.route_evidence.iter().any(|evidence| {
            evidence.evidence_kind == "coding.route.classification.v1"
                && evidence.route_id == template_id
        }));
        assert!(run.route_evidence.iter().any(|evidence| {
            evidence.evidence_kind == "coding.route.skill_selection.v1"
                && evidence
                    .selected_skill_hashes
                    .iter()
                    .any(|hash| hash == expected_skill_hash)
        }));
        assert!(run.route_evidence.iter().any(|evidence| {
            evidence.evidence_kind == "coding.route.gate.v1"
                && evidence
                    .gate_result
                    .as_ref()
                    .map(|gate| gate.status.as_str())
                    == Some("pass")
        }));
        assert!(run.verification_evidence.iter().any(|evidence| {
            evidence.evidence_type == "coding.route.gate.v1" && evidence.status == "pass"
        }));
        assert!(run.route_run_summary.as_ref().is_some_and(|summary| {
            summary.route_id == template_id
                && !summary.gate_results.is_empty()
                && summary
                    .benchmark_results
                    .iter()
                    .any(|result| result.selected_skill_hash == expected_skill_hash)
                && summary
                    .promotion_decisions
                    .iter()
                    .any(|decision| decision.skill_hash == expected_skill_hash)
        }));
    }
}

#[test]
fn coding_route_promotion_loop_promotes_draft_skill_with_evidence() {
    let root = temp_root("route-promotion-loop");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "coding.template.build".to_string(),
        name: Some("Promotion Loop Build".to_string()),
    })
    .expect("route template should create");
    let run = run_workflow_project(
        bundle.workflow_path,
        Some(json!({
            "skillCatalog": [
                {
                    "skillHash": "draft-incremental",
                    "name": "incremental-implementation",
                    "description": "Draft incremental implementation guidance.",
                    "lifecycleState": "Draft",
                    "sourceType": "runtime_skill_source_draft",
                    "successRateBps": 0,
                    "sampleSize": 0,
                    "relativePath": "skills/incremental-implementation/SKILL.md",
                    "stale": false,
                    "markdown": "Work in small slices and verify each change.",
                    "phaseTags": ["coding.build", "coding.verify"],
                    "routeTags": ["coding.template.build"],
                    "promotionEvidenceRefs": []
                }
            ]
        })),
    )
    .expect("route should run with draft benchmark skill");
    assert_eq!(run.summary.status, "passed");
    let summary = run
        .route_run_summary
        .as_ref()
        .expect("route run summary should exist");
    assert_eq!(summary.route_id, "coding.template.build");
    assert!(summary
        .selected_skills
        .iter()
        .any(|skill| skill.skill_hash == "draft-incremental" && skill.lifecycle_state == "Draft"));
    assert!(summary
        .gate_results
        .iter()
        .any(|gate| gate.gate_id == "route.verify.execution"
            && gate.status == "pass"
            && gate.operator_override_allowed == false));
    assert!(summary
        .benchmark_results
        .iter()
        .any(|result| result.selected_skill_hash == "draft-incremental"
            && result.promotion_decision == "promote"));
    assert!(summary
        .promotion_decisions
        .iter()
        .any(|decision| decision.skill_hash == "draft-incremental"
            && decision.decision == "promote"
            && decision.to_lifecycle_state == "Promoted"));
    assert!(run.route_evidence.iter().any(|evidence| {
        evidence.evidence_kind == "coding.route.benchmark.v1"
            && evidence
                .benchmark_results
                .iter()
                .any(|result| result.selected_skill_hash == "draft-incremental")
    }));
    assert!(run.route_evidence.iter().any(|evidence| {
        evidence.evidence_kind == "coding.route.promotion.v1"
            && evidence
                .promotion_decisions
                .iter()
                .any(|decision| decision.skill_hash == "draft-incremental")
    }));
}

#[test]
fn coding_route_classifier_defaults_to_build_and_detects_debug_or_review() {
    for (name, expected_route) in [
        (
            "Implement sidebar workflow controls",
            "coding.template.build",
        ),
        ("Debug failing route validation", "coding.template.debug"),
        (
            "Review security sensitive workflow patch",
            "coding.template.review",
        ),
    ] {
        let root = temp_root(&format!(
            "route-classifier-{}",
            expected_route.replace('.', "-")
        ));
        let bundle = create_workflow_project(CreateWorkflowProjectRequest {
            project_root: root.display().to_string(),
            name: name.to_string(),
            workflow_kind: "agent_workflow".to_string(),
            execution_mode: "local".to_string(),
            template_id: None,
        })
        .expect("workflow bundle should create");
        let mut source = workflow_node(
            "route-source",
            "source",
            "Route source",
            80,
            120,
            "Input",
            "manual",
        );
        logic_mut(&mut source).insert("payload".to_string(), json!({"request": name}));
        let output = workflow_node(
            "route-output",
            "output",
            "Route output",
            320,
            120,
            "Output",
            "report",
        );
        let mut workflow = bundle.workflow.clone();
        workflow.nodes = vec![source, output];
        workflow.edges = vec![workflow_edge(
            "edge-route-source-output",
            "route-source",
            "route-output",
        )];
        save_workflow_project(bundle.workflow_path.clone(), workflow)
            .expect("workflow should save");

        let run = run_workflow_project(bundle.workflow_path, None).expect("workflow should run");
        assert_eq!(run.summary.status, "passed");
        assert!(run.route_evidence.iter().any(|evidence| {
            evidence.evidence_kind == "coding.route.classification.v1"
                && evidence.route_id == expected_route
        }));
    }
}

#[test]
fn workflow_skill_context_pinned_name_ambiguity_blocks() {
    let root = temp_root("skill-context-ambiguous");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Skill Context Ambiguity".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");
    let source = workflow_node(
        "ambiguous-source",
        "source",
        "Goal",
        80,
        120,
        "Input",
        "manual",
    );
    let mut skill_context = workflow_node(
        "skill-context",
        "skill_context",
        "Runtime skills",
        320,
        120,
        "Skills",
        "pinned",
    );
    logic_mut(&mut skill_context).insert(
        "skillContext".to_string(),
        json!({
            "mode": "pinned",
            "pinnedSkills": [{ "name": "frontend-skill", "required": true }],
            "onMissingPinned": "block",
            "includeMarkdown": true,
            "guidanceMaxChars": 1800
        }),
    );
    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, skill_context];
    workflow.edges = vec![workflow_edge(
        "edge-source-skill-context",
        "ambiguous-source",
        "skill-context",
    )];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run = run_workflow_project(
        bundle.workflow_path,
        Some(json!({
            "skillCatalog": [
                {
                    "skillHash": "skill-front-a",
                    "name": "frontend-skill",
                    "description": "First frontend skill.",
                    "lifecycleState": "promoted",
                    "sourceType": "runtime_registry",
                    "successRateBps": 9000,
                    "sampleSize": 10,
                    "relativePath": "a/SKILL.md",
                    "stale": false,
                    "markdown": "First"
                },
                {
                    "skillHash": "skill-front-b",
                    "name": "frontend-skill",
                    "description": "Second frontend skill.",
                    "lifecycleState": "promoted",
                    "sourceType": "runtime_registry",
                    "successRateBps": 9000,
                    "sampleSize": 10,
                    "relativePath": "b/SKILL.md",
                    "stale": false,
                    "markdown": "Second"
                }
            ]
        })),
    )
    .expect("workflow should run");
    assert_eq!(run.summary.status, "failed");
    assert!(run.node_runs.iter().any(|node_run| {
        node_run.node_id == "skill-context"
            && node_run
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("matched 2 skills")
    }));
}

#[test]
fn workflow_tool_argument_schema_blocks_malformed_tool_call() {
    let root = temp_root("tool-argument-schema");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Tool Argument Schema".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");
    let source = workflow_node(
        "tool-source",
        "source",
        "Input",
        80,
        160,
        "Input",
        "payload",
    );
    let mut tool = workflow_node(
        "schema-tool",
        "plugin_tool",
        "Schema tool",
        320,
        160,
        "Tool",
        "mock.search",
    );
    logic_mut(&mut tool).insert(
        "toolBinding".to_string(),
        json!({
            "toolRef": "mock.search",
            "bindingKind": "plugin_tool",
            "mockBinding": true,
            "credentialReady": true,
            "capabilityScope": ["read"],
            "sideEffectClass": "read",
            "requiresApproval": false,
            "arguments": {},
            "argumentSchema": { "type": "object", "required": ["q"] },
            "resultSchema": { "type": "object", "required": ["toolRef", "arguments", "input"] }
        }),
    );
    let output = workflow_node(
        "tool-output",
        "output",
        "Output",
        560,
        160,
        "Output",
        "summary",
    );
    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, tool, output];
    workflow.edges = vec![
        workflow_edge("edge-source-tool", "tool-source", "schema-tool"),
        workflow_edge("edge-tool-output", "schema-tool", "tool-output"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run = run_workflow_project(bundle.workflow_path, None).expect("workflow should run");
    assert_ne!(run.summary.status, "passed");
    assert!(run
        .node_runs
        .iter()
        .any(|node_run| node_run.node_id == "schema-tool"
            && node_run
                .error
                .as_deref()
                .unwrap_or_default()
                .contains("Tool arguments failed schema validation")));
}

#[test]
fn workflow_parser_node_satisfies_model_parser_attachment() {
    let root = temp_root("parser-primitive");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Parser Primitive".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let source = workflow_node(
        "source-data",
        "source",
        "Source data",
        80,
        120,
        "Input",
        "payload",
    );
    let parser = workflow_node(
        "parser-json",
        "parser",
        "JSON parser",
        320,
        260,
        "Parser",
        "schema",
    );
    let mut model = workflow_node(
        "model-plan",
        "model_call",
        "Plan response",
        320,
        120,
        "Model",
        "reasoning",
    );
    logic_mut(&mut model).insert("parserRef".to_string(), json!("json_schema"));
    logic_mut(&mut model).insert(
        "outputSchema".to_string(),
        json!({"type": "object", "properties": {"message": {"type": "string"}}}),
    );
    let output = workflow_node(
        "output-report",
        "output",
        "Output",
        580,
        120,
        "Output",
        "markdown",
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, parser, model, output];
    workflow.edges = vec![
        workflow_edge("edge-source-model", "source-data", "model-plan"),
        json!({
            "id": "edge-parser-model",
            "from": "parser-json",
            "to": "model-plan",
            "fromPort": "parser",
            "toPort": "parser",
            "type": "data",
            "connectionClass": "parser",
            "data": { "connectionClass": "parser" }
        }),
        workflow_edge("edge-model-output", "model-plan", "output-report"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow.clone())
        .expect("workflow should save");
    let passed =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(passed.status, "passed");
    assert!(!passed
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "missing_model_parser_attachment"));

    let parser_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("parser-json"))
        .expect("parser should exist");
    logic_mut(parser_node).insert(
        "parserBinding".to_string(),
        json!({
            "parserRef": "json_schema",
            "parserKind": "json_schema",
            "mockBinding": true
        }),
    );
    logic_mut(parser_node).remove("outputSchema");
    save_workflow_project(bundle.workflow_path, workflow).expect("workflow should save");
    let blocked = validate_workflow_bundle(
        root.join(".agents/workflows/parser-primitive.workflow.json")
            .display()
            .to_string(),
    )
    .expect("validation should run");
    assert_eq!(blocked.status, "blocked");
    assert!(blocked
        .verification_issues
        .iter()
        .any(|issue| issue.code == "missing_parser_result_schema"));
}

#[test]
fn workflow_model_binding_node_satisfies_model_attachment() {
    let root = temp_root("model-binding-primitive");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Model Binding Primitive".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let source = workflow_node(
        "source-data",
        "source",
        "Source data",
        80,
        120,
        "Input",
        "payload",
    );
    let binding = workflow_node(
        "model-binding",
        "model_binding",
        "Reasoning binding",
        320,
        260,
        "Model",
        "reasoning",
    );
    let mut model = workflow_node(
        "model-plan",
        "model_call",
        "Plan response",
        320,
        120,
        "Model",
        "reasoning",
    );
    logic_mut(&mut model).remove("modelRef");
    let output = workflow_node(
        "output-report",
        "output",
        "Output",
        580,
        120,
        "Output",
        "markdown",
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, binding, model, output];
    workflow.edges = vec![
        workflow_edge("edge-source-model", "source-data", "model-plan"),
        json!({
            "id": "edge-model-binding-model",
            "from": "model-binding",
            "to": "model-plan",
            "fromPort": "model",
            "toPort": "model",
            "type": "data",
            "connectionClass": "model",
            "data": { "connectionClass": "model" }
        }),
        workflow_edge("edge-model-output", "model-plan", "output-report"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow.clone())
        .expect("workflow should save");
    let passed =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(passed.status, "passed");
    assert!(!passed
        .missing_config
        .iter()
        .any(|issue| issue.code == "missing_model_binding"));

    let run = run_workflow_project(bundle.workflow_path.clone(), None)
        .expect("workflow should run with attached model binding");
    assert_eq!(run.summary.status, "passed");
    let model_output = run
        .final_state
        .node_outputs
        .get("model-plan")
        .expect("model output should exist");
    assert_eq!(
        model_output.get("modelRef").and_then(Value::as_str),
        Some("reasoning")
    );

    let binding_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("model-binding"))
        .expect("model binding should exist");
    logic_mut(binding_node).insert(
        "modelBinding".to_string(),
        json!({
            "modelRef": "reasoning",
            "mockBinding": true,
            "capabilityScope": ["reasoning"],
            "sideEffectClass": "none",
            "requiresApproval": false,
            "credentialReady": false,
            "toolUseMode": "none"
        }),
    );
    logic_mut(binding_node).remove("outputSchema");
    save_workflow_project(bundle.workflow_path, workflow).expect("workflow should save");
    let blocked = validate_workflow_bundle(
        root.join(".agents/workflows/model-binding-primitive.workflow.json")
            .display()
            .to_string(),
    )
    .expect("validation should run");
    assert_eq!(blocked.status, "blocked");
    assert!(blocked
        .verification_issues
        .iter()
        .any(|issue| issue.code == "missing_model_binding_result_schema"));
}

#[test]
fn workflow_port_class_defaults_reject_edge_class_spoofing() {
    let root = temp_root("port-class-spoofing");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Port Class Spoofing".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let source = workflow_node(
        "source-data",
        "source",
        "Source data",
        80,
        120,
        "Input",
        "payload",
    );
    let mut model = workflow_node(
        "model-plan",
        "model_call",
        "Plan response",
        320,
        120,
        "Model",
        "reasoning",
    );
    logic_mut(&mut model).insert("parserRef".to_string(), json!("json_schema"));
    logic_mut(&mut model).insert("outputSchema".to_string(), json!({"type": "object"}));
    let output = workflow_node(
        "output-report",
        "output",
        "Output",
        580,
        120,
        "Output",
        "markdown",
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, model, output];
    workflow.edges = vec![
        json!({
            "id": "edge-source-parser-spoof",
            "from": "source-data",
            "to": "model-plan",
            "fromPort": "output",
            "toPort": "parser",
            "type": "data",
            "connectionClass": "parser",
            "data": { "connectionClass": "parser" }
        }),
        workflow_edge("edge-model-output", "model-plan", "output-report"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation = validate_workflow_bundle(bundle.workflow_path).expect("validation should run");
    assert_eq!(validation.status, "failed");
    assert!(validation
        .errors
        .iter()
        .any(|issue| issue.code == "invalid_connection_class"));
}

#[test]
fn blank_workflow_can_be_authored_from_scratch_and_run() {
    let root = temp_root("scratch");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Scratch Heavy Agent".to_string(),
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
            "Normalize request",
            320,
            170,
            "return { result: { normalized: true, input } };",
        ),
        workflow_node(
            "scratch-output",
            "output",
            "Scratch report",
            580,
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
            "edge-scratch-function-output",
            "scratch-function",
            "scratch-output",
        ),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");
    save_workflow_tests(
        bundle.workflow_path.clone(),
        vec![workflow_test(
            "test-scratch-path",
            "Scratch nodes exist",
            vec!["scratch-source", "scratch-function", "scratch-output"],
        )],
    )
    .expect("tests should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");
    let tests = run_workflow_tests(bundle.workflow_path.clone(), None).expect("tests should run");
    assert_eq!(tests.status, "passed");
    let run = run_workflow_project(bundle.workflow_path, None).expect("run should execute");
    assert_eq!(run.summary.status, "passed");
    assert!(run
        .completion_requirements
        .iter()
        .all(|requirement| requirement.status == "satisfied"));
}

#[test]
fn scratch_graph_validation_rejects_backwards_entry_and_terminal_edges() {
    let root = temp_root("scratch-invalid-edges");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Scratch Invalid Edges".to_string(),
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
            "Normalize request",
            320,
            170,
            "return { result: { normalized: true, input } };",
        ),
        workflow_node(
            "scratch-output",
            "output",
            "Scratch report",
            580,
            180,
            "Output",
            "report",
        ),
    ];
    workflow.edges = vec![
        workflow_edge("edge-function-source", "scratch-function", "scratch-source"),
        workflow_edge("edge-output-function", "scratch-output", "scratch-function"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation = validate_workflow_bundle(bundle.workflow_path).expect("validation should run");
    assert_eq!(validation.status, "failed");
    assert!(validation
        .errors
        .iter()
        .any(|issue| issue.code == "invalid_source_input_edge"));
    assert!(validation
        .errors
        .iter()
        .any(|issue| issue.code == "invalid_output_edge"));
}
