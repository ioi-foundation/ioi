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

