use super::*;

fn temp_root(label: &str) -> PathBuf {
    let root = std::env::temp_dir().join(format!("autopilot-workflow-{}-{}", label, now_ms()));
    if root.exists() {
        fs::remove_dir_all(&root).expect("clear old workflow test root");
    }
    fs::create_dir_all(&root).expect("create workflow test root");
    root
}

fn logic_mut(node: &mut Value) -> &mut serde_json::Map<String, Value> {
    node.get_mut("config")
        .and_then(|config| config.get_mut("logic"))
        .and_then(Value::as_object_mut)
        .expect("node logic object")
}

#[test]
fn create_workflow_project_writes_bundle_sidecars() {
    let root = temp_root("create");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Email Review".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    assert!(bundle
        .workflow_path
        .ends_with(".agents/workflows/email-review.workflow.json"));
    assert!(bundle
        .tests_path
        .ends_with(".agents/workflows/email-review.tests.json"));
    assert!(bundle
        .proposals_dir
        .ends_with(".agents/workflows/email-review.proposals"));
    assert!(PathBuf::from(&bundle.workflow_path).exists());
    assert!(PathBuf::from(&bundle.tests_path).exists());
    assert!(PathBuf::from(&bundle.proposals_dir).is_dir());
    assert!(bundle.workflow.nodes.is_empty());
    assert!(bundle.workflow.edges.is_empty());
    assert!(bundle.tests.is_empty());
    assert_eq!(bundle.runs.len(), 0);
}

#[test]
fn workflow_scaffolds_include_action_metadata() {
    let root = temp_root("scaffold-actions");
    let scaffolds = list_workflow_scaffolds(root.display().to_string())
        .expect("workflow scaffolds should list");
    let model = scaffolds
        .iter()
        .find(|item| item.get("nodeType").and_then(Value::as_str) == Some("model_call"))
        .expect("model_call scaffold should exist");
    let action = model.get("action").expect("action metadata should exist");
    assert_eq!(
        action.get("requiredBinding").and_then(Value::as_str),
        Some("model")
    );
    assert_eq!(
        action.get("bindingMode").and_then(Value::as_str),
        Some("required")
    );
    assert!(action
        .get("connectionClasses")
        .and_then(Value::as_array)
        .expect("connection classes")
        .iter()
        .any(|class| class.as_str() == Some("tool")));
    let media = scaffolds
        .iter()
        .find(|item| {
            item.get("scaffoldId").and_then(Value::as_str) == Some("workflow.source.media")
        })
        .expect("media input action scaffold should exist");
    assert_eq!(
        media.get("nodeType").and_then(Value::as_str),
        Some("source")
    );
    assert_eq!(
        media.get("label").and_then(Value::as_str),
        Some("Media input")
    );
    assert_eq!(
        media
            .get("presetLogic")
            .and_then(|logic| logic.get("sourceKind"))
            .and_then(Value::as_str),
        Some("media")
    );
    assert_eq!(
        media
            .get("presetLogic")
            .and_then(|logic| logic.get("fileExtension"))
            .and_then(Value::as_str),
        Some("jpg")
    );
    let connector_write = scaffolds
        .iter()
        .find(|item| {
            item.get("scaffoldId").and_then(Value::as_str) == Some("workflow.adapter.write")
        })
        .expect("connector write action scaffold should exist");
    assert_eq!(
        connector_write
            .get("action")
            .and_then(|action| action.get("requiresApproval"))
            .and_then(Value::as_bool),
        Some(true)
    );
    let proposal = scaffolds
        .iter()
        .find(|item| item.get("nodeType").and_then(Value::as_str) == Some("proposal"))
        .expect("proposal scaffold should exist");
    assert_eq!(
        proposal
            .get("action")
            .and_then(|action| action.get("requiresApproval"))
            .and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn workflow_scaffold_creation_applies_action_variant_preset() {
    let root = temp_root("scaffold-create");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Scaffold Variant Create".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");
    let bundle = create_workflow_node_from_scaffold(
        bundle.workflow_path,
        CreateWorkflowNodeFromScaffoldRequest {
            scaffold_id: "workflow.source.media".to_string(),
            node_id: Some("media-source".to_string()),
            name: None,
            x: None,
            y: None,
        },
    )
    .expect("media source scaffold should create");
    let node = bundle
        .workflow
        .nodes
        .iter()
        .find(|node| node.get("id").and_then(Value::as_str) == Some("media-source"))
        .expect("media node should exist");
    assert_eq!(node.get("type").and_then(Value::as_str), Some("source"));
    let logic = node
        .get("config")
        .and_then(|config| config.get("logic"))
        .expect("node logic should exist");
    assert_eq!(
        logic.get("sourceKind").and_then(Value::as_str),
        Some("media")
    );
    assert_eq!(
        logic.get("mediaKind").and_then(Value::as_str),
        Some("image")
    );
    assert_eq!(
        logic.get("fileExtension").and_then(Value::as_str),
        Some("jpg")
    );
    assert_eq!(
        logic.get("validateMime").and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn workflow_validation_uses_action_metadata_for_required_bindings() {
    let root = temp_root("action-binding-validation");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Action Binding Validation".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");
    let source = workflow_node("source", "source", "Input", 120, 160, "Input", "manual");
    let mut adapter = workflow_node(
        "adapter",
        "adapter",
        "Connector read",
        360,
        160,
        "Connector",
        "mock.crm.read",
    );
    logic_mut(&mut adapter).remove("connectorBinding");
    let output = workflow_node("output", "output", "Output", 600, 160, "Output", "markdown");
    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, adapter, output];
    workflow.edges = vec![
        workflow_edge("edge-source-adapter", "source", "adapter"),
        workflow_edge("edge-adapter-output", "adapter", "output"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation = validate_workflow_bundle(bundle.workflow_path).expect("validation should run");
    assert_eq!(validation.status, "blocked");
    assert!(validation.missing_config.iter().any(|issue| {
        issue.node_id.as_deref() == Some("adapter") && issue.code == "missing_action_binding"
    }));
}

#[test]
fn workflow_node_fixtures_persist_as_sidecars() {
    let root = temp_root("fixtures");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Fixture Replay".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");
    let mut workflow = bundle.workflow.clone();
    let mut source = workflow_node(
        "source-1",
        "source",
        "Source sample",
        120,
        160,
        "Source",
        "ready",
    );
    logic_mut(&mut source).insert(
        "outputSchema".to_string(),
        json!({"type": "object", "required": ["message"]}),
    );
    workflow.nodes = vec![source];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let fixture = WorkflowNodeFixture {
        id: "fixture-source-1".to_string(),
        node_id: "source-1".to_string(),
        name: "Source sample".to_string(),
        input: Some(json!({"request": "hello"})),
        output: Some(json!({"message": "world"})),
        schema_hash: Some("schema-a".to_string()),
        node_config_hash: Some("config-a".to_string()),
        source_run_id: Some("run-a".to_string()),
        pinned: None,
        stale: Some(false),
        validation_status: None,
        validation_message: None,
        created_at_ms: now_ms(),
    };

    let saved = save_workflow_node_fixture(bundle.workflow_path.clone(), fixture.clone())
        .expect("fixture should save");
    assert_eq!(saved.len(), 1);
    assert!(PathBuf::from(
        bundle
            .workflow_path
            .replace(".workflow.json", ".fixtures.json")
    )
    .exists());

    let all = list_workflow_node_fixtures(
        root.join(".agents/workflows/fixture-replay.workflow.json")
            .display()
            .to_string(),
        None,
    )
    .expect("fixtures should load");
    assert_eq!(all[0].id, fixture.id);
    assert_eq!(all[0].validation_status.as_deref(), Some("passed"));

    let mut pinned_fixture = fixture.clone();
    pinned_fixture.id = "fixture-source-2".to_string();
    pinned_fixture.name = "Pinned Source sample".to_string();
    pinned_fixture.pinned = Some(true);
    pinned_fixture.created_at_ms = now_ms();
    let pinned_saved = save_workflow_node_fixture(bundle.workflow_path.clone(), pinned_fixture)
        .expect("pinned fixture should save");
    assert_eq!(pinned_saved[0].id, "fixture-source-2");
    assert_eq!(pinned_saved[0].pinned, Some(true));
    assert_eq!(pinned_saved[1].pinned, Some(false));

    let filtered = list_workflow_node_fixtures(
        root.join(".agents/workflows/fixture-replay.workflow.json")
            .display()
            .to_string(),
        Some("missing-node".to_string()),
    )
    .expect("filtered fixtures should load");
    assert!(filtered.is_empty());
}

#[test]
fn workflow_binding_check_uses_typed_runtime_and_hidden_evidence() {
    let root = temp_root("binding-check");
    let mut bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Binding Check".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");
    bundle.workflow.global_config["environmentProfile"] = json!({
        "target": "production",
        "credentialScope": "local",
        "mockBindingPolicy": "block"
    });

    let mut adapter = workflow_node(
        "adapter-slack",
        "adapter",
        "Slack read",
        120,
        160,
        "Connector",
        "mock",
    );
    logic_mut(&mut adapter).insert(
        "connectorBinding".to_string(),
        json!({
            "connectorRef": "slack.mock",
            "mockBinding": true,
            "credentialReady": false,
            "capabilityScope": ["read"],
            "sideEffectClass": "read",
            "requiresApproval": false
        }),
    );
    let mut model = workflow_node(
        "model-plan",
        "model_call",
        "Plan response",
        360,
        160,
        "Model",
        "ready",
    );
    logic_mut(&mut model).insert(
        "modelBinding".to_string(),
        json!({
            "modelRef": "reasoning",
            "mockBinding": false,
            "credentialReady": true,
            "capabilityScope": ["reasoning"],
            "sideEffectClass": "none",
            "requiresApproval": false
        }),
    );
    bundle.workflow.nodes.push(adapter);
    bundle.workflow.nodes.push(model);
    save_workflow_project(bundle.workflow_path.clone(), bundle.workflow)
        .expect("workflow should save with binding nodes");

    let blocked = check_workflow_binding(
        bundle.workflow_path.clone(),
        "adapter-slack".to_string(),
        Some("adapter-slack-connector".to_string()),
    )
    .expect("mock connector binding should check");
    assert_eq!(blocked.status, "blocked");
    assert_eq!(blocked.binding_kind, "Connector");
    assert!(blocked.detail.contains("explicitly mocked"));

    let passed = check_workflow_binding(
        bundle.workflow_path.clone(),
        "model-plan".to_string(),
        Some("model-plan-model".to_string()),
    )
    .expect("ready model binding should check");
    assert_eq!(passed.status, "passed");
    assert!(passed
        .detail
        .contains("No hidden vendor connectivity probe was run"));

    let evidence = list_workflow_evidence(bundle.workflow_path.clone())
        .expect("binding check evidence should load");
    assert!(evidence
        .iter()
        .any(|entry| entry.kind == "binding_check" && entry.path.is_none()));
}

#[test]
fn workflow_binding_manifest_persists_environment_sidecar() {
    let root = temp_root("binding-manifest");
    let mut bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Binding Manifest".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");
    bundle.workflow.global_config["environmentProfile"] = json!({
        "target": "sandbox",
        "credentialScope": "sandbox",
        "mockBindingPolicy": "warn"
    });

    let mut adapter = workflow_node(
        "adapter-support",
        "adapter",
        "Support connector",
        120,
        160,
        "Connector",
        "mock",
    );
    logic_mut(&mut adapter).insert(
        "connectorBinding".to_string(),
        json!({
            "connectorRef": "support.mock",
            "mockBinding": true,
            "credentialReady": false,
            "capabilityScope": ["read", "ticket_draft"],
            "sideEffectClass": "write",
            "requiresApproval": true
        }),
    );
    let mut tool = workflow_node(
        "tool-child-workflow",
        "plugin_tool",
        "Workflow tool",
        360,
        160,
        "Tool",
        "local",
    );
    logic_mut(&mut tool).insert(
        "toolBinding".to_string(),
        json!({
            "bindingKind": "workflow_tool",
            "toolRef": "workflow.local",
            "workflowTool": { "workflowPath": ".agents/workflows/child.workflow.json" },
            "capabilityScope": ["subgraph"],
            "sideEffectClass": "none",
            "requiresApproval": false
        }),
    );
    bundle.workflow.nodes.push(adapter);
    bundle.workflow.nodes.push(tool);
    save_workflow_project(bundle.workflow_path.clone(), bundle.workflow)
        .expect("workflow should save with binding nodes");

    let manifest = generate_workflow_binding_manifest(bundle.workflow_path.clone())
        .expect("manifest should generate");
    assert_eq!(manifest.schema_version, "workflow.bindings.v1");
    assert_eq!(manifest.workflow_slug, "binding-manifest");
    assert_eq!(manifest.summary.total, 2);
    assert_eq!(manifest.summary.mock_bindings, 1);
    assert_eq!(manifest.summary.local, 1);
    assert_eq!(manifest.summary.ready, 2);
    assert_eq!(manifest.summary.approval_required, 1);
    assert!(manifest
        .bindings
        .iter()
        .any(|entry| entry.id == "adapter-support-connector"
            && entry.mode == "mock"
            && entry.status == "warning"));

    let workflow_path = PathBuf::from(&bundle.workflow_path);
    let manifest_path = workflow_binding_manifest_path(&workflow_path);
    assert!(manifest_path.exists());
    let saved_workflow = fs::read_to_string(&workflow_path).expect("workflow should read");
    assert!(!saved_workflow.contains("bindingManifest"));

    let loaded = load_workflow_binding_manifest(bundle.workflow_path.clone())
        .expect("manifest should load")
        .expect("manifest should exist");
    assert_eq!(loaded.summary.total, manifest.summary.total);

    let evidence = list_workflow_evidence(bundle.workflow_path).expect("evidence should load");
    assert!(evidence
        .iter()
        .any(|entry| entry.kind == "binding_manifest" && entry.path.is_none()));
}

#[test]
fn legacy_artifact_nodes_normalize_to_output_nodes_on_load_and_save() {
    let root = temp_root("legacy-output-normalization");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Legacy Output Migration".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let workflow_path = PathBuf::from(&bundle.workflow_path);
    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![workflow_node(
        "legacy-output",
        "output",
        "Legacy report",
        80,
        180,
        "Output",
        "report",
    )];
    workflow.nodes[0]["type"] = json!("artifact");
    logic_mut(&mut workflow.nodes[0]).insert("path".to_string(), json!("reports/legacy-report.md"));
    write_json_pretty(&workflow_path, &workflow).expect("legacy workflow should write");

    let loaded = load_workflow_bundle(bundle.workflow_path.clone()).expect("legacy should load");
    assert_eq!(
        loaded.workflow.nodes[0].get("type").and_then(Value::as_str),
        Some("output")
    );
    assert_eq!(
        loaded.workflow.nodes[0]
            .get("config")
            .and_then(|config| config.get("logic"))
            .and_then(|logic| logic.get("materialization"))
            .and_then(|materialization| materialization.get("assetPath"))
            .and_then(Value::as_str),
        Some("reports/legacy-report.md")
    );

    save_workflow_project(bundle.workflow_path.clone(), loaded.workflow)
        .expect("normalized workflow should save");
    let saved = fs::read_to_string(&workflow_path).expect("saved workflow should read");
    assert!(!saved.contains(r#""type": "artifact""#));
    assert!(saved.contains(r#""type": "output""#));
}

#[test]
fn workflow_expression_refs_require_connected_output_ports() {
    let root = temp_root("expression-validation");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Expression Validation".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut source = workflow_node(
        "source-data",
        "source",
        "Source data",
        80,
        120,
        "Input",
        "payload",
    );
    logic_mut(&mut source).insert("payload".to_string(), json!({ "payload": "sample" }));
    let mut function = workflow_function_node(
        "function-map",
        "Map input",
        320,
        120,
        "return { result: input };",
    );
    logic_mut(&mut function).insert(
        "inputMapping".to_string(),
        json!({ "input": "{{nodes.source-data.output}}" }),
    );
    let output = workflow_node(
        "output-report",
        "output",
        "Output",
        560,
        120,
        "Output",
        "markdown",
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, function, output];
    workflow.edges = vec![workflow_edge(
        "edge-function-output",
        "function-map",
        "output-report",
    )];
    save_workflow_project(bundle.workflow_path.clone(), workflow.clone())
        .expect("workflow should save");

    let blocked =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(blocked.status, "blocked");
    assert!(blocked
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "unconnected_expression_ref"));

    workflow.edges.insert(
        0,
        workflow_edge("edge-source-function", "source-data", "function-map"),
    );
    save_workflow_project(bundle.workflow_path.clone(), workflow)
        .expect("connected workflow should save");
    let passed = validate_workflow_bundle(bundle.workflow_path).expect("validation should run");
    assert_eq!(passed.status, "passed");
}

#[test]
fn workflow_field_mappings_require_declared_schema_paths() {
    let root = temp_root("field-mapping-validation");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Field Mapping Validation".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut source = workflow_node(
        "source-data",
        "source",
        "Source data",
        80,
        120,
        "Input",
        "payload",
    );
    logic_mut(&mut source).insert(
        "schema".to_string(),
        json!({
            "type": "object",
            "properties": {
                "payload": {
                    "type": "object",
                    "properties": {
                        "title": { "type": "string" }
                    }
                }
            }
        }),
    );
    let mut function = workflow_function_node(
        "function-map",
        "Map input",
        320,
        120,
        "return { result: input };",
    );
    logic_mut(&mut function).insert(
        "fieldMappings".to_string(),
        json!({
            "missing_field": {
                "source": "{{nodes.source-data.output}}",
                "path": "payload.missing",
                "type": "string"
            }
        }),
    );
    let output = workflow_node(
        "output-report",
        "output",
        "Output",
        560,
        120,
        "Output",
        "markdown",
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, function, output];
    workflow.edges = vec![
        workflow_edge("edge-source-function", "source-data", "function-map"),
        workflow_edge("edge-function-output", "function-map", "output-report"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow.clone())
        .expect("workflow should save");

    let blocked =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(blocked.status, "blocked");
    assert!(blocked
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "missing_field_mapping_path"));

    let function_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("function-map"))
        .expect("function should exist");
    logic_mut(function_node).insert(
        "fieldMappings".to_string(),
        json!({
            "title": {
                "source": "{{nodes.source-data.output}}",
                "path": "payload.title",
                "type": "string"
            }
        }),
    );
    save_workflow_project(bundle.workflow_path.clone(), workflow)
        .expect("connected workflow should save");
    let passed = validate_workflow_bundle(bundle.workflow_path).expect("validation should run");
    assert_eq!(passed.status, "passed");
}

#[test]
fn workflow_field_mappings_prepare_runtime_node_input() {
    let root = temp_root("field-mapping-runtime");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Field Mapping Runtime".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut source = workflow_node(
        "source-data",
        "source",
        "Source data",
        80,
        120,
        "Input",
        "payload",
    );
    logic_mut(&mut source).insert(
        "payload".to_string(),
        json!({ "title": "Mapped title", "body": "ignored" }),
    );
    logic_mut(&mut source).insert(
        "schema".to_string(),
        json!({
            "type": "object",
            "properties": {
                "payload": {
                    "type": "object",
                    "properties": {
                        "title": { "type": "string" },
                        "body": { "type": "string" }
                    }
                }
            }
        }),
    );
    let mut function = workflow_function_node(
        "function-map",
        "Map title",
        320,
        120,
        "return { mappedTitle: input.title };",
    );
    logic_mut(&mut function).insert(
        "fieldMappings".to_string(),
        json!({
            "title": {
                "source": "{{nodes.source-data.output}}",
                "path": "payload.title",
                "type": "string"
            }
        }),
    );
    logic_mut(&mut function).insert(
        "functionBinding".to_string(),
        json!({
            "language": "javascript",
            "code": "return { mappedTitle: input.title };",
            "outputSchema": {
                "type": "object",
                "required": ["mappedTitle"],
                "properties": {
                    "mappedTitle": { "type": "string" }
                }
            },
            "sandboxPolicy": {
                "timeoutMs": 1000,
                "memoryMb": 64,
                "outputLimitBytes": 32768,
                "permissions": []
            },
            "testInput": { "title": "Mapped title" }
        }),
    );
    let output = workflow_node(
        "output-report",
        "output",
        "Output",
        560,
        120,
        "Output",
        "markdown",
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, function, output];
    workflow.edges = vec![
        workflow_edge("edge-source-function", "source-data", "function-map"),
        workflow_edge("edge-function-output", "function-map", "output-report"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run = run_workflow_project(bundle.workflow_path, None).expect("run should execute");
    assert_eq!(run.summary.status, "passed");
    let function_run = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "function-map")
        .expect("function should run");
    assert_eq!(function_run.input, Some(json!({ "title": "Mapped title" })));
    assert_eq!(
        function_run
            .output
            .as_ref()
            .and_then(|output| output.get("result"))
            .and_then(|result| result.get("mappedTitle"))
            .and_then(Value::as_str),
        Some("Mapped title")
    );
}

#[test]
fn workflow_model_configuration_requires_typed_attachments_and_result_schema() {
    let root = temp_root("model-configuration-validation");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Model Configuration Validation".to_string(),
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
        "Plan with tools",
        320,
        120,
        "Model",
        "reasoning",
    );
    logic_mut(&mut model).insert("toolUseMode".to_string(), json!("explicit"));
    logic_mut(&mut model).insert("parserRef".to_string(), json!("json-parser"));
    logic_mut(&mut model).insert("memoryKey".to_string(), json!("user_memory"));
    logic_mut(&mut model).insert("validateStructuredOutput".to_string(), json!(true));
    logic_mut(&mut model).remove("outputSchema");
    let tool = workflow_node(
        "tool-search",
        "plugin_tool",
        "Search tool",
        320,
        300,
        "Plugin",
        "mock.search",
    );
    let state = workflow_node(
        "state-memory",
        "state",
        "User memory",
        320,
        540,
        "State",
        "memory",
    );
    let parser = workflow_node(
        "parser-json",
        "parser",
        "JSON parser",
        320,
        430,
        "Parser",
        "schema",
    );
    let output = workflow_node(
        "output-report",
        "output",
        "Output",
        560,
        120,
        "Output",
        "markdown",
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, model, tool, parser, state, output];
    workflow.edges = vec![
        workflow_edge("edge-source-model", "source-data", "model-plan"),
        workflow_edge("edge-model-output", "model-plan", "output-report"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow.clone())
        .expect("workflow should save");

    let blocked =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(blocked.status, "blocked");
    assert!(blocked
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "missing_model_tool_attachment"));
    assert!(blocked
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "missing_model_parser_attachment"));
    assert!(blocked
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "missing_model_memory_attachment"));
    assert!(blocked
        .verification_issues
        .iter()
        .any(|issue| issue.code == "missing_model_output_schema"));

    let model_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("model-plan"))
        .expect("model should exist");
    logic_mut(model_node).insert(
        "outputSchema".to_string(),
        json!({
            "type": "object",
            "properties": {
                "message": { "type": "string" }
            }
        }),
    );
    workflow.edges.extend([
        json!({
            "id": "edge-tool-model",
            "from": "tool-search",
            "to": "model-plan",
            "fromPort": "tool",
            "toPort": "tool",
            "type": "data",
            "connectionClass": "tool",
            "data": { "connectionClass": "tool" }
        }),
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
        json!({
            "id": "edge-memory-model",
            "from": "state-memory",
            "to": "model-plan",
            "fromPort": "memory",
            "toPort": "memory",
            "type": "data",
            "connectionClass": "memory",
            "data": { "connectionClass": "memory" }
        }),
    ]);
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");
    let passed = validate_workflow_bundle(bundle.workflow_path).expect("validation should run");
    assert_eq!(passed.status, "passed");
}

#[test]
fn workflow_model_tool_memory_parser_loop_records_lineage() {
    let root = temp_root("model-loop-lineage");
    let bundle = create_workflow_project(CreateWorkflowProjectRequest {
        project_root: root.display().to_string(),
        name: "Model Loop Lineage".to_string(),
        workflow_kind: "agent_workflow".to_string(),
        execution_mode: "local".to_string(),
        template_id: None,
    })
    .expect("workflow bundle should create");

    let mut source = workflow_node(
        "loop-source",
        "source",
        "Prompt input",
        80,
        180,
        "Input",
        "payload",
    );
    logic_mut(&mut source).insert(
        "payload".to_string(),
        json!({"prompt": "Summarize prior memory and tool results."}),
    );
    let mut state = workflow_node(
        "loop-memory",
        "state",
        "Memory",
        300,
        260,
        "State",
        "memory",
    );
    logic_mut(&mut state).insert("stateKey".to_string(), json!("conversation"));
    logic_mut(&mut state).insert("stateOperation".to_string(), json!("merge"));
    let model_binding = workflow_node(
        "loop-model-binding",
        "model_binding",
        "Reasoning model",
        300,
        30,
        "Binding",
        "reasoning",
    );
    let mut parser = workflow_node(
        "loop-parser",
        "parser",
        "JSON parser",
        300,
        390,
        "Parser",
        "schema",
    );
    logic_mut(&mut parser).insert(
        "parserBinding".to_string(),
        json!({
            "parserRef": "json_schema",
            "parserKind": "json_schema",
            "resultSchema": { "type": "object", "required": ["message"] },
            "mockBinding": true
        }),
    );
    let mut tool = workflow_node(
        "loop-tool",
        "plugin_tool",
        "Search tool",
        300,
        520,
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
            "arguments": { "q": "memory" },
            "argumentSchema": { "type": "object", "required": ["q"] },
            "resultSchema": { "type": "object", "required": ["toolRef", "arguments", "input"] }
        }),
    );
    let mut model = workflow_node(
        "loop-model",
        "model_call",
        "Model with attachments",
        560,
        180,
        "Model",
        "reasoning",
    );
    logic_mut(&mut model).insert("toolUseMode".to_string(), json!("explicit"));
    logic_mut(&mut model).insert("parserRef".to_string(), json!("json_schema"));
    logic_mut(&mut model).insert("memoryKey".to_string(), json!("conversation"));
    logic_mut(&mut model).insert(
        "outputSchema".to_string(),
        json!({"type": "object", "required": ["message", "attachments", "toolCalls"]}),
    );
    let output = workflow_node(
        "loop-output",
        "output",
        "Output",
        820,
        180,
        "Output",
        "summary",
    );

    let mut workflow = bundle.workflow.clone();
    workflow.nodes = vec![source, state, model_binding, parser, tool, model, output];
    workflow.edges = vec![
        workflow_edge("edge-source-memory", "loop-source", "loop-memory"),
        json!({
            "id": "edge-model-binding-model",
            "from": "loop-model-binding",
            "to": "loop-model",
            "fromPort": "model",
            "toPort": "model",
            "type": "model",
            "connectionClass": "model",
            "data": { "connectionClass": "model" }
        }),
        json!({
            "id": "edge-memory-model",
            "from": "loop-memory",
            "to": "loop-model",
            "fromPort": "memory",
            "toPort": "memory",
            "type": "data",
            "connectionClass": "memory",
            "data": { "connectionClass": "memory" }
        }),
        json!({
            "id": "edge-parser-model",
            "from": "loop-parser",
            "to": "loop-model",
            "fromPort": "parser",
            "toPort": "parser",
            "type": "data",
            "connectionClass": "parser",
            "data": { "connectionClass": "parser" }
        }),
        json!({
            "id": "edge-tool-model",
            "from": "loop-tool",
            "to": "loop-model",
            "fromPort": "tool",
            "toPort": "tool",
            "type": "data",
            "connectionClass": "tool",
            "data": { "connectionClass": "tool" }
        }),
        workflow_edge("edge-model-output", "loop-model", "loop-output"),
    ];
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");
    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "passed");

    let run = run_workflow_project(bundle.workflow_path, None).expect("workflow should run");
    assert_eq!(run.summary.status, "passed");
    let model_output = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "loop-model")
        .and_then(|node_run| node_run.output.as_ref())
        .expect("model output should exist");
    assert_eq!(
        model_output
            .pointer("/attachments/parser/kind")
            .and_then(Value::as_str),
        Some("parser")
    );
    assert_eq!(
        model_output
            .pointer("/attachments/memory/kind")
            .and_then(Value::as_str),
        Some("state")
    );
    assert_eq!(
        model_output
            .pointer("/toolCalls/0/toolName")
            .and_then(Value::as_str),
        Some("mock.search")
    );
    let tool_output = run
        .node_runs
        .iter()
        .find(|node_run| node_run.node_id == "loop-tool")
        .and_then(|node_run| node_run.output.as_ref())
        .expect("tool output should exist");
    assert_eq!(
        tool_output
            .pointer("/result/toolRef")
            .and_then(Value::as_str),
        Some("mock.search")
    );
    assert_eq!(
        tool_output
            .pointer("/argumentSchema/required/0")
            .and_then(Value::as_str),
        Some("q")
    );
    assert!(run.events.iter().any(|event| event.kind == "node_succeeded"
        && event.node_id.as_deref() == Some("loop-model")
        && event
            .state_delta
            .as_ref()
            .map(|updates| !updates.is_empty())
            .unwrap_or(false)));
}

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

#[test]
fn workflow_function_dry_run_executes_in_sandbox_and_records_evidence() {
    let root = temp_root("function-dry-run");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("Function Sandbox".to_string()),
    })
    .expect("template should instantiate");

    let mut workflow = bundle.workflow.clone();
    let function_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("function-summarize"))
        .expect("function node exists");
    let logic = logic_mut(function_node);
    logic.insert(
        "functionBinding".to_string(),
        json!({
            "language": "javascript",
            "code": "console.log('scan-ok'); return { summary: 'ok', count: input.items.length };",
            "inputSchema": { "type": "object" },
            "outputSchema": { "type": "object", "required": ["summary", "count"] },
            "sandboxPolicy": {
                "timeoutMs": 1000,
                "memoryMb": 64,
                "outputLimitBytes": 4096,
                "permissions": []
            },
            "testInput": { "items": [1, 2, 3] }
        }),
    );
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run = dry_run_workflow_function(
        bundle.workflow_path,
        "function-summarize".to_string(),
        Some(json!({ "items": [1, 2, 3] })),
    )
    .expect("function dry run should execute");
    assert_eq!(run.summary.status, "passed");
    assert_eq!(
        run.node_runs[0]
            .input
            .as_ref()
            .and_then(|input| input.pointer("/items/2"))
            .and_then(Value::as_i64),
        Some(3)
    );
    let output = run.node_runs[0].output.as_ref().expect("node output");
    assert_eq!(
        output.pointer("/result/summary").and_then(Value::as_str),
        Some("ok")
    );
    assert_eq!(
        output.pointer("/result/count").and_then(Value::as_i64),
        Some(3)
    );
    assert!(output
        .get("stdout")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .contains("scan-ok"));
    assert!(run
        .verification_evidence
        .iter()
        .any(|evidence| evidence.node_id == "function-summarize" && evidence.status == "passed"));
}

#[test]
fn workflow_function_materializes_and_executes_file_backed_source() {
    let root = temp_root("function-file-backed");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("File Backed Function".to_string()),
    })
    .expect("template should instantiate");

    let materialized = materialize_workflow_function(
        bundle.workflow_path.clone(),
        "function-summarize".to_string(),
        None,
    )
    .expect("function should materialize");
    let function_node = materialized
        .workflow
        .nodes
        .iter()
        .find(|node| workflow_node_id(node).as_deref() == Some("function-summarize"))
        .expect("function node exists");
    let function_ref = workflow_node_logic(function_node)
        .pointer("/functionBinding/functionRef")
        .cloned()
        .expect("function ref should exist");
    let source_path = function_ref
        .get("sourcePath")
        .and_then(Value::as_str)
        .expect("source path should exist");
    assert_eq!(
        function_ref
            .get("codeHash")
            .and_then(Value::as_str)
            .map(str::len),
        Some(64)
    );
    assert_eq!(
        function_ref
            .pointer("/dependencyManifest/runtime")
            .and_then(Value::as_str),
        Some("node")
    );
    fs::write(
        source_path,
        "return { summary: 'file-backed', count: input.items.length };",
    )
    .expect("function source should be editable");

    let run = dry_run_workflow_function(
        bundle.workflow_path,
        "function-summarize".to_string(),
        Some(json!({ "items": [1, 2, 3, 4] })),
    )
    .expect("file-backed function should execute");
    assert_eq!(run.summary.status, "passed");
    let output = run.node_runs[0].output.as_ref().expect("node output");
    assert_eq!(
        output.pointer("/result/summary").and_then(Value::as_str),
        Some("file-backed")
    );
    assert_eq!(
        output.get("codeHash").and_then(Value::as_str).map(str::len),
        Some(64)
    );
}

#[test]
fn workflow_function_blocks_undeclared_filesystem_access() {
    let root = temp_root("unsafe-function");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("Unsafe Function".to_string()),
    })
    .expect("template should instantiate");

    let mut workflow = bundle.workflow.clone();
    let function_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("function-summarize"))
        .expect("function node exists");
    logic_mut(function_node).insert(
            "functionBinding".to_string(),
            json!({
                "language": "javascript",
                "code": "const fs = require('fs'); return { summary: fs.readFileSync('/etc/passwd', 'utf8') };",
                "outputSchema": { "type": "object", "required": ["summary"] },
                "sandboxPolicy": {
                    "timeoutMs": 1000,
                    "memoryMb": 64,
                    "outputLimitBytes": 4096,
                    "permissions": []
                },
                "testInput": {}
            }),
        );
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "blocked");
    assert!(validation
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "unsafe_function_permission"));
    let run =
        dry_run_workflow_function(bundle.workflow_path, "function-summarize".to_string(), None)
            .expect("dry run should return structured blocker");
    assert_eq!(run.summary.status, "blocked");
    assert!(run.node_runs[0]
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("filesystem"));
}

#[test]
fn workflow_function_validates_input_schema_and_captures_stderr() {
    let root = temp_root("function-input-schema");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("Function Input Schema".to_string()),
    })
    .expect("template should instantiate");

    let mut workflow = bundle.workflow.clone();
    let function_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("function-summarize"))
        .expect("function node exists");
    logic_mut(function_node).insert(
        "functionBinding".to_string(),
        json!({
            "language": "javascript",
            "code": "console.error('schema-ok'); return { summary: input.title.toUpperCase() };",
            "inputSchema": { "type": "object", "required": ["title"] },
            "outputSchema": { "type": "object", "required": ["summary"] },
            "sandboxPolicy": {
                "timeoutMs": 1000,
                "memoryMb": 64,
                "outputLimitBytes": 4096,
                "permissions": []
            },
            "testInput": { "title": "ready" }
        }),
    );
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run = dry_run_workflow_function(
        bundle.workflow_path.clone(),
        "function-summarize".to_string(),
        Some(json!({ "title": "ready" })),
    )
    .expect("valid function input should run");
    assert_eq!(run.summary.status, "passed");
    let output = run.node_runs[0].output.as_ref().expect("node output");
    assert_eq!(
        output.pointer("/result/summary").and_then(Value::as_str),
        Some("READY")
    );
    assert!(output
        .get("stderr")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .contains("schema-ok"));

    let blocked = dry_run_workflow_function(
        bundle.workflow_path,
        "function-summarize".to_string(),
        Some(json!({ "body": "missing title" })),
    )
    .expect("invalid function input should return a structured blocker");
    assert_eq!(blocked.summary.status, "blocked");
    assert!(blocked.node_runs[0]
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("Function input failed schema validation"));
}

#[test]
fn workflow_function_blocks_unsupported_dependency_manifest() {
    let root = temp_root("function-dependencies");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("Function Dependency Manifest".to_string()),
    })
    .expect("template should instantiate");

    let mut materialized = materialize_workflow_function(
        bundle.workflow_path.clone(),
        "function-summarize".to_string(),
        None,
    )
    .expect("function should materialize");
    let function_node = materialized
        .workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("function-summarize"))
        .expect("function node exists");
    logic_mut(function_node)
        .get_mut("functionBinding")
        .expect("function binding should exist")
        .pointer_mut("/functionRef/dependencyManifest/dependencies")
        .expect("dependency manifest should exist")
        .as_object_mut()
        .expect("dependencies should be an object")
        .insert("lodash".to_string(), json!("^4.17.21"));
    save_workflow_project(bundle.workflow_path.clone(), materialized.workflow)
        .expect("workflow should save");

    let validation =
        validate_workflow_bundle(bundle.workflow_path.clone()).expect("validation should run");
    assert_eq!(validation.status, "blocked");
    assert!(validation
        .execution_readiness_issues
        .iter()
        .any(|issue| issue.code == "unsupported_function_dependency"));

    let run =
        dry_run_workflow_function(bundle.workflow_path, "function-summarize".to_string(), None)
            .expect("dependency issue should return a structured blocker");
    assert_eq!(run.summary.status, "blocked");
    assert!(run.node_runs[0]
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("unsupported external dependencies"));
}

#[test]
fn workflow_function_blocks_output_over_sandbox_limit() {
    let root = temp_root("function-output-limit");
    let bundle = create_workflow_from_template(CreateWorkflowFromTemplateRequest {
        project_root: root.display().to_string(),
        template_id: "repo-function-test".to_string(),
        name: Some("Function Output Limit".to_string()),
    })
    .expect("template should instantiate");

    let mut workflow = bundle.workflow.clone();
    let function_node = workflow
        .nodes
        .iter_mut()
        .find(|node| workflow_node_id(node).as_deref() == Some("function-summarize"))
        .expect("function node exists");
    logic_mut(function_node).insert(
        "functionBinding".to_string(),
        json!({
            "language": "javascript",
            "code": "return { summary: 'oversized', payload: 'x'.repeat(5000) };",
            "outputSchema": { "type": "object", "required": ["summary", "payload"] },
            "sandboxPolicy": {
                "timeoutMs": 1000,
                "memoryMb": 64,
                "outputLimitBytes": 1024,
                "permissions": []
            },
            "testInput": {}
        }),
    );
    save_workflow_project(bundle.workflow_path.clone(), workflow).expect("workflow should save");

    let run =
        dry_run_workflow_function(bundle.workflow_path, "function-summarize".to_string(), None)
            .expect("oversized output should return a structured blocker");
    assert_eq!(run.summary.status, "blocked");
    assert!(run.node_runs[0]
        .error
        .as_deref()
        .unwrap_or_default()
        .contains("output limit"));
}

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
