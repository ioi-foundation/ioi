#[test]
fn workflow_runtime_requires_explicit_connector_and_tool_bindings() {
    let root = temp_root("typed-bindings");
    let adapter_bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "adapter-connector-check".to_string(),
        name: Some("Missing Connector Binding".to_string()),
    })
    .expect("adapter template should instantiate");
    let mut adapter_workflow = adapter_bundle.workflow.clone();
    let adapter_node = adapter_workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("adapter-read"))
        .expect("adapter node exists");
    logic_mut(adapter_node).remove("connectorBinding");
    save_workflow_project(adapter_bundle.workflow_path.clone(), adapter_workflow)
        .expect("adapter workflow should save");
    let adapter_validation = validate_workflow_bundle(adapter_bundle.workflow_path.clone())
        .expect("adapter validation should run");
    assert_eq!(adapter_validation.status, "blocked");
    assert!(adapter_validation
        .connector_binding_issues
        .iter()
        .any(|issue| issue.code == "missing_connector_binding"));
    let adapter_run =
        run_workflow_project(adapter_bundle.workflow_path, None).expect("run should block");
    assert_eq!(adapter_run.summary.status, "blocked");

    let plugin_bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "plugin-tool-action".to_string(),
        name: Some("Missing Tool Binding".to_string()),
    })
    .expect("plugin template should instantiate");
    let mut plugin_workflow = plugin_bundle.workflow.clone();
    let plugin_node = plugin_workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("plugin-codex"))
        .expect("plugin node exists");
    logic_mut(plugin_node).remove("toolBinding");
    save_workflow_project(plugin_bundle.workflow_path.clone(), plugin_workflow)
        .expect("plugin workflow should save");
    let plugin_validation = validate_workflow_bundle(plugin_bundle.workflow_path.clone())
        .expect("plugin validation should run");
    assert_eq!(plugin_validation.status, "blocked");
    assert!(plugin_validation
        .connector_binding_issues
        .iter()
        .any(|issue| issue.code == "missing_tool_binding"));
    let plugin_run =
        run_workflow_project(plugin_bundle.workflow_path, None).expect("run should block");
    assert_eq!(plugin_run.summary.status, "blocked");
}

#[test]
fn workflow_tool_binding_invokes_child_workflow() {
    let root = temp_root("workflow-tool");
    let child_bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("Child Tool Workflow".to_string()),
    })
    .expect("child workflow should instantiate");

    let parent_bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Parent Workflow Tool".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("parent workflow should create");
    let mut parent = parent_bundle.workflow.clone();
    parent.nodes = vec![
        workflow_node(
            "parent-source",
            "source",
            "Parent input",
            120,
            180,
            "Input",
            "manual",
        ),
        workflow_node(
            "parent-tool",
            "plugin_tool",
            "Call child workflow",
            380,
            180,
            "Tool",
            "workflow_tool",
        ),
        workflow_node(
            "parent-output",
            "output",
            "Parent output",
            640,
            180,
            "Output",
            "summary",
        ),
    ];
    parent.edges = vec![
        workflow_edge("edge-source-tool", "parent-source", "parent-tool"),
        workflow_edge("edge-tool-output", "parent-tool", "parent-output"),
    ];
    let tool_node = parent
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("parent-tool"))
        .expect("tool node exists");
    let child_workflow_file = Path::new(&child_bundle.workflow_path)
        .file_name()
        .and_then(|name| name.to_str())
        .expect("child workflow file name");
    let child_workflow_ref = format!(".agents/workflows/{}", child_workflow_file);
    logic_mut(tool_node).insert(
        "toolBinding".to_string(),
        json!({
            "toolRef": "workflow_tool",
            "bindingKind": "workflow_tool",
            "mockBinding": false,
            "capabilityScope": ["invoke"],
            "sideEffectClass": "read",
            "requiresApproval": false,
            "arguments": { "task": "summarize child run" },
            "workflowTool": {
                "workflowPath": child_workflow_ref,
                "argumentSchema": { "type": "object" },
                "resultSchema": { "type": "object" },
                "timeoutMs": 30000,
                "maxAttempts": 1
            }
        }),
    );
    save_workflow_project(parent_bundle.workflow_path.clone(), parent)
        .expect("parent workflow should save");
    save_workflow_tests(
        parent_bundle.workflow_path.clone(),
        vec![WorkflowTestCase {
            id: "test-parent-tool-node".to_string(),
            name: "Parent tool node exists".to_string(),
            target_node_ids: vec!["parent-tool".to_string()],
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
    .expect("parent tests should save");

    let validation = validate_workflow_bundle(parent_bundle.workflow_path.clone())
        .expect("validation should run");
    assert_eq!(validation.status, "passed");
    assert!(!validation
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "live_tool_side_effect_unavailable"));

    let run = run_workflow_project(parent_bundle.workflow_path, None).expect("run should execute");
    assert_eq!(run.summary.status, "passed");
    let tool_output = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "parent-tool")
        .and_then(|node_run| node_run.output.as_ref())
        .expect("tool output");
    assert_eq!(
        tool_output.get("toolKind").and_then(Value::as_str),
        Some("workflow_tool")
    );
    assert_eq!(
        tool_output.get("childRunStatus").and_then(Value::as_str),
        Some("passed")
    );
    assert_eq!(tool_output.get("attempt").and_then(Value::as_u64), Some(1));
    assert_eq!(
        tool_output.get("maxAttempts").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        tool_output.get("timeoutMs").and_then(Value::as_u64),
        Some(30000)
    );
    assert_eq!(
        tool_output
            .get("argumentSchema")
            .and_then(|schema| schema.get("type"))
            .and_then(Value::as_str),
        Some("object")
    );
    assert_eq!(
        tool_output
            .get("resultSchema")
            .and_then(|schema| schema.get("type"))
            .and_then(Value::as_str),
        Some("object")
    );
    assert!(run.events.iter().any(|event| {
        event.kind == "child_run_completed"
            && event.node_id.as_deref() == Some("parent-tool")
            && event.status.as_deref() == Some("passed")
    }));
}

#[test]
fn workflow_tool_binding_requires_schema_and_retry_contract() {
    let root = temp_root("workflow-tool-contract");
    let child_bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("Child Tool Contract".to_string()),
    })
    .expect("child workflow should instantiate");
    let parent_bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Parent Workflow Tool Contract".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("parent workflow should create");
    let mut parent = parent_bundle.workflow.clone();
    parent.nodes = vec![workflow_node(
        "parent-tool",
        "plugin_tool",
        "Call child workflow",
        380,
        180,
        "Tool",
        "workflow_tool",
    )];
    let tool_node = parent
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("parent-tool"))
        .expect("tool node exists");
    logic_mut(tool_node).insert(
        "toolBinding".to_string(),
        json!({
            "toolRef": "workflow_tool",
            "bindingKind": "workflow_tool",
            "mockBinding": false,
            "capabilityScope": ["invoke"],
            "sideEffectClass": "read",
            "requiresApproval": false,
            "arguments": {},
            "workflowTool": {
                "workflowPath": child_bundle.workflow_path,
                "timeoutMs": 0,
                "maxAttempts": 0
            }
        }),
    );
    save_workflow_project(parent_bundle.workflow_path.clone(), parent)
        .expect("parent workflow should save");

    let validation = validate_workflow_bundle(parent_bundle.workflow_path.clone())
        .expect("validation should run");
    assert_eq!(validation.status, "blocked");
    assert!(validation
        .verification_issues
        .iter()
        .any(|issue| issue.code == "missing_workflow_tool_argument_schema"));
    assert!(validation
        .verification_issues
        .iter()
        .any(|issue| issue.code == "missing_workflow_tool_result_schema"));
    assert!(validation
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "invalid_workflow_tool_timeout"));
    assert!(validation
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "invalid_workflow_tool_attempts"));

    let mut repaired = load_workflow_bundle(parent_bundle.workflow_path.clone())
        .expect("parent workflow should load")
        .workflow;
    let repaired_tool = repaired
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("parent-tool"))
        .expect("tool node exists");
    let binding = logic_mut(repaired_tool)
        .get_mut("toolBinding")
        .and_then(Value::as_object_mut)
        .expect("binding object");
    let workflow_tool = binding
        .get_mut("workflowTool")
        .and_then(Value::as_object_mut)
        .expect("workflow tool object");
    workflow_tool.insert("argumentSchema".to_string(), json!({ "type": "object" }));
    workflow_tool.insert("resultSchema".to_string(), json!({ "type": "object" }));
    workflow_tool.insert("timeoutMs".to_string(), json!(30000));
    workflow_tool.insert("maxAttempts".to_string(), json!(2));
    save_workflow_project(parent_bundle.workflow_path.clone(), repaired)
        .expect("repaired workflow should save");
    let repaired_validation = validate_workflow_bundle(parent_bundle.workflow_path)
        .expect("repaired validation should run");
    assert!(!repaired_validation
        .verification_issues
        .iter()
        .any(|issue| issue.code.starts_with("missing_workflow_tool_")));
    assert!(!repaired_validation
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code.starts_with("invalid_workflow_tool_")));
}

#[test]
fn workflow_tool_runtime_validates_argument_and_result_schema() {
    let root = temp_root("workflow-tool-runtime-schema");
    let child_bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "basic-agent-answer".to_string(),
        name: Some("Child Runtime Schema".to_string()),
    })
    .expect("child workflow should instantiate");
    let child_workflow_file = Path::new(&child_bundle.workflow_path)
        .file_name()
        .and_then(|name| name.to_str())
        .expect("child workflow file name");
    let child_workflow_ref = format!(".agents/workflows/{}", child_workflow_file);

    let parent_bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Parent Runtime Schema".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("parent workflow should create");
    let mut parent = parent_bundle.workflow.clone();
    parent.nodes = vec![workflow_node(
        "parent-tool",
        "plugin_tool",
        "Call child workflow",
        380,
        180,
        "Tool",
        "workflow_tool",
    )];
    let tool_node = parent
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("parent-tool"))
        .expect("tool node exists");
    logic_mut(tool_node).insert(
        "toolBinding".to_string(),
        json!({
            "toolRef": "workflow_tool",
            "bindingKind": "workflow_tool",
            "mockBinding": false,
            "capabilityScope": ["invoke"],
            "sideEffectClass": "read",
            "requiresApproval": false,
            "arguments": {},
            "workflowTool": {
                "workflowPath": child_workflow_ref,
                "argumentSchema": {
                    "type": "object",
                    "required": ["task"],
                    "properties": {
                        "task": { "type": "string" }
                    }
                },
                "resultSchema": { "type": "object" },
                "timeoutMs": 30000,
                "maxAttempts": 2
            }
        }),
    );
    save_workflow_project(parent_bundle.workflow_path.clone(), parent)
        .expect("parent workflow should save");

    let argument_failure =
        run_workflow_project(parent_bundle.workflow_path.clone(), None).expect("run should finish");
    assert_eq!(argument_failure.summary.status, "failed");
    let argument_error = argument_failure
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "parent-tool")
        .and_then(|node_run| node_run.error.as_deref())
        .expect("argument schema error");
    assert!(argument_error.contains("Workflow tool arguments failed schema validation"));

    let mut repaired = load_workflow_bundle(parent_bundle.workflow_path.clone())
        .expect("parent workflow should load")
        .workflow;
    let repaired_tool = repaired
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("parent-tool"))
        .expect("tool node exists");
    let binding = logic_mut(repaired_tool)
        .get_mut("toolBinding")
        .and_then(Value::as_object_mut)
        .expect("binding object");
    binding.insert("arguments".to_string(), json!({ "task": "run child" }));
    let workflow_tool = binding
        .get_mut("workflowTool")
        .and_then(Value::as_object_mut)
        .expect("workflow tool object");
    workflow_tool.insert(
        "resultSchema".to_string(),
        json!({
            "type": "object",
            "required": ["missingChildResult"],
            "properties": {
                "missingChildResult": { "type": "string" }
            }
        }),
    );
    save_workflow_project(parent_bundle.workflow_path.clone(), repaired)
        .expect("parent workflow should save");

    let result_failure =
        run_workflow_project(parent_bundle.workflow_path, None).expect("run should finish");
    assert_eq!(result_failure.summary.status, "failed");
    let result_error = result_failure
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "parent-tool")
        .and_then(|node_run| node_run.error.as_deref())
        .expect("result schema error");
    assert!(result_error.contains("Workflow tool result failed schema validation"));
}

#[test]
fn live_connector_and_tool_bindings_require_ready_credentials() {
    let root = temp_root("live-binding-credentials");
    let adapter_bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "adapter-connector-check".to_string(),
        name: Some("Live Connector Credentials".to_string()),
    })
    .expect("adapter template should instantiate");
    let mut adapter_workflow = adapter_bundle.workflow.clone();
    let adapter_node = adapter_workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("adapter-read"))
        .expect("adapter node exists");
    let connector_binding = logic_mut(adapter_node)
        .get_mut("connectorBinding")
        .and_then(Value::as_object_mut)
        .expect("connector binding");
    connector_binding.insert("mockBinding".to_string(), Value::Bool(false));
    connector_binding.insert("credentialReady".to_string(), Value::Bool(false));
    save_workflow_project(adapter_bundle.workflow_path.clone(), adapter_workflow)
        .expect("adapter workflow should save");
    let adapter_validation = validate_workflow_bundle(adapter_bundle.workflow_path.clone())
        .expect("adapter validation should run");
    assert!(adapter_validation
        .connector_binding_issues
        .iter()
        .any(|issue| issue.code == "missing_live_connector_credential"));

    let plugin_bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "plugin-tool-action".to_string(),
        name: Some("Live Tool Credentials".to_string()),
    })
    .expect("plugin template should instantiate");
    let mut plugin_workflow = plugin_bundle.workflow.clone();
    let plugin_node = plugin_workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("plugin-codex"))
        .expect("plugin node exists");
    let tool_binding = logic_mut(plugin_node)
        .get_mut("toolBinding")
        .and_then(Value::as_object_mut)
        .expect("tool binding");
    tool_binding.insert("mockBinding".to_string(), Value::Bool(false));
    tool_binding.insert("credentialReady".to_string(), Value::Bool(false));
    save_workflow_project(plugin_bundle.workflow_path.clone(), plugin_workflow)
        .expect("plugin workflow should save");
    let plugin_validation = validate_workflow_bundle(plugin_bundle.workflow_path.clone())
        .expect("plugin validation should run");
    assert!(plugin_validation
        .connector_binding_issues
        .iter()
        .any(|issue| issue.code == "missing_live_tool_credential"));
}

#[test]
fn workflow_tool_side_effect_pauses_for_contextual_approval() {
    let root = temp_root("tool-approval-interrupt");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Contextual Tool Approval".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow should create");

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![
        workflow_node(
            "approval-source",
            "source",
            "Approval input",
            120,
            180,
            "Input",
            "manual",
        ),
        workflow_node(
            "approval-tool",
            "plugin_tool",
            "Draft external update",
            380,
            180,
            "Tool",
            "mock",
        ),
        workflow_node(
            "approval-output",
            "output",
            "Approval output",
            640,
            180,
            "Output",
            "summary",
        ),
    ];
    workflow.edges = vec![
        workflow_edge("edge-source-tool", "approval-source", "approval-tool"),
        workflow_edge("edge-tool-output", "approval-tool", "approval-output"),
    ];
    let tool_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("approval-tool"))
        .expect("tool node exists");
    logic_mut(tool_node).insert(
        "toolBinding".to_string(),
        json!({
            "toolRef": "ticket_draft_tool",
            "bindingKind": "plugin_tool",
            "mockBinding": true,
            "capabilityScope": ["write"],
            "sideEffectClass": "external_write",
            "requiresApproval": true,
            "arguments": { "ticket": "approval-required" }
        }),
    );
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");
    assert!(validation.policy_required_nodes.is_empty());

    let interrupted =
        run_workflow_project(bundle.workflow_path.clone(), None).expect("run should pause");
    assert_eq!(interrupted.summary.status, "interrupted");
    assert_eq!(
        interrupted
            .interrupt
            .as_ref()
            .map(|interrupt| interrupt.node_id.as_str()),
        Some("approval-tool")
    );
    let preview = interrupted
        .interrupt
        .as_ref()
        .and_then(|interrupt| interrupt.response.as_ref())
        .expect("approval preview should be recorded");
    assert_eq!(
        preview
            .get("binding")
            .and_then(|binding| binding.get("sideEffectClass"))
            .and_then(Value::as_str),
        Some("external_write")
    );

    let resumed = resume_workflow_run(
        bundle.workflow_path,
        WorkflowResumeRequest {
            run_id: Some(interrupted.summary.id.clone()),
            thread_id: interrupted.thread.id.clone(),
            node_id: None,
            interrupt_id: interrupted.interrupt.as_ref().map(|item| item.id.clone()),
            checkpoint_id: interrupted.thread.latest_checkpoint_id.clone(),
            outcome: "approve".to_string(),
            edited_state: None,
        },
    )
    .expect("approved tool run should resume");
    assert_eq!(resumed.summary.status, "passed");
    assert!(resumed.node_runs.iter().any(|node_run| {
        node_run.node_id == "approval-tool"
            && node_run.node_type == "plugin_tool"
            && node_run.status == "success"
    }));
}

#[test]
fn workflow_output_delivery_pauses_for_contextual_approval() {
    let root = temp_root("output-delivery-approval");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Output Delivery Approval".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow should create");

    let source = workflow_node(
        "delivery-source",
        "source",
        "Delivery input",
        120,
        180,
        "Input",
        "manual",
    );
    let mut output = workflow_node(
        "delivery-output",
        "output",
        "Connector delivery draft",
        380,
        180,
        "Output",
        "summary",
    );
    logic_mut(&mut output).insert(
        "deliveryTarget".to_string(),
        json!({
            "targetKind": "connector_write",
            "destination": "mock.ticket.create",
            "requiresApproval": true
        }),
    );
    logic_mut(&mut output).insert("sideEffectClass".to_string(), json!("external_write"));
    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, output];
    workflow.edges = vec![workflow_edge(
        "edge-source-output",
        "delivery-source",
        "delivery-output",
    )];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");
    assert!(!validation
        .policy_required_nodes
        .iter()
        .any(|node_id| node_id == "delivery-output"));

    let interrupted =
        run_workflow_project(bundle.workflow_path.clone(), None).expect("run should pause");
    assert_eq!(interrupted.summary.status, "interrupted");
    assert_eq!(
        interrupted
            .interrupt
            .as_ref()
            .map(|interrupt| interrupt.node_id.as_str()),
        Some("delivery-output")
    );
    let preview = interrupted
        .interrupt
        .as_ref()
        .and_then(|interrupt| interrupt.response.as_ref())
        .expect("delivery approval preview");
    assert_eq!(
        preview
            .get("binding")
            .and_then(|binding| binding.get("bindingKind"))
            .and_then(Value::as_str),
        Some("delivery")
    );
    assert_eq!(
        preview
            .get("binding")
            .and_then(|binding| binding.get("sideEffectClass"))
            .and_then(Value::as_str),
        Some("external_write")
    );

    let resumed = resume_workflow_run(
        bundle.workflow_path,
        WorkflowResumeRequest {
            run_id: Some(interrupted.summary.id.clone()),
            thread_id: interrupted.thread.id.clone(),
            node_id: None,
            interrupt_id: interrupted.interrupt.as_ref().map(|item| item.id.clone()),
            checkpoint_id: interrupted.thread.latest_checkpoint_id.clone(),
            outcome: "approve".to_string(),
            edited_state: None,
        },
    )
    .expect("approved delivery should resume");
    assert_eq!(resumed.summary.status, "passed");
    assert!(resumed.node_runs.iter().any(|node_run| {
        node_run.node_id == "delivery-output"
            && node_run.node_type == "output"
            && node_run.status == "success"
    }));
}

#[test]
fn workflow_policy_is_contextual_for_pure_transform_and_privileged_writes() {
    let root = temp_root("policy");
    let media_bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "heavy-media-transform".to_string(),
        name: Some("Media Transform".to_string()),
    })
    .expect("media template should instantiate");
    let media_validation =
        validate_workflow_bundle(media_bundle.workflow_path).expect("validation should run");
    assert_eq!(media_validation.status, "passed");
    assert!(media_validation.policy_required_nodes.is_empty());

    let triage_bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "heavy-connector-triage".to_string(),
        name: Some("Live Write Triage".to_string()),
    })
    .expect("triage template should instantiate");
    let mut workflow = triage_bundle.workflow.clone();
    let ticket_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("adapter-ticket-draft"))
        .expect("ticket adapter exists");
    let binding = logic_mut(ticket_node)
        .get_mut("connectorBinding")
        .and_then(Value::as_object_mut)
        .expect("connector binding");
    binding.insert("mockBinding".to_string(), Value::Bool(false));
    binding.insert("sideEffectClass".to_string(), json!("external_write"));
    save_workflow_project(triage_bundle.workflow_path.clone(), workflow)
        .expect("workflow should save");
    let validation =
        validate_workflow_bundle(triage_bundle.workflow_path).expect("validation should run");
    assert_eq!(validation.status, "blocked");
    assert!(validation
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "live_connector_write_unavailable"));
}

