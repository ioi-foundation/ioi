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

